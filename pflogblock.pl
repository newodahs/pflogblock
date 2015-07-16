#!/usr/local/bin/perl -w
# Copyright (c) 2015, Seth Jeacopello 
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of pflogblock nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use Sys::Syslog qw(:standard :macros);
use Getopt::Long;
use IO::Poll qw(POLLIN POLLERR POLLHUP);
use File::Basename;
use File::Which;
use Socket qw(:addrinfo SOCK_RAW);

# general constants
use constant
{
   PFLOG_BLOCK_TABLENAME => 'pflogblock',
   DEFAULT_SCRIPT_NAME => 'pflogblock',
   BLACKLIST_EXPIRE_TIME => 86400,
   VERSION => '1.0.0_1'
};

# security regex constants
use constant DEFAULT_SECREGEX_LIST => ['Invalid user [a-zA-Z0-9\-\$_]+ from ([a-zA-Z0-9\.\-:]*)', 
                                       'Did not receive identification string from ([a-zA-Z0-9\.\-:]*)'];

# filename constant
use constant
{
   FILENAME_BLACKLIST => "/var/db/@{[PFLOG_BLOCK_TABLENAME]}_blacklist",
   FILENAME_WHITELIST => "/var/db/@{[PFLOG_BLOCK_TABLENAME]}_whitelist",
   FILENAME_TMPBLACKLIST => '/tmp/.pflogblock.old',
   FILENAME_SECREGEX => '/usr/local/etc/pflogblock_regex.conf'
};

# globals used for script, directory and suffix of this script
my ($_SCRIPT_NAME, $_DIRECTORY, $_SUFFIX) = fileparse($0);

# Grab the script name minus the extension -- used for syslog
my $_SCRIPT_NAME_NOEXT = $_SCRIPT_NAME;
$_SCRIPT_NAME_NOEXT =~ s/\.pl$//;
$_SCRIPT_NAME_NOEXT = $_SCRIPT_NAME_NOEXT || DEFAULT_SCRIPT_NAME;

# Grab pfctl command location (or use default)
my $_PFCTL_CMD = which('pfctl');

sub commitBlacklist
{
   my $blacklist = $_[0];
   my $strBlacklist = "";

   syslog(LOG_DEBUG, "Committing Blacklist (Saving to @{[FILENAME_BLACKLIST]})");

   # Replace our blacklist file...
   open(BLACKLIST, '>', FILENAME_BLACKLIST) || die("Could not open @{[FILENAME_BLACKLIST]}");
   foreach my $listItem (@{$blacklist})
   {
      syslog(LOG_DEBUG, "Saving blacklist entry: $listItem");
      print(BLACKLIST "$listItem\n");
   }
   close(BLACKLIST);

   # reload the blacklist into pf...
   &loadBlacklistDB(@{[FILENAME_BLACKLIST]});
}

sub expireBlacklist
{
   my $expireTime = $_[0];
   syslog(LOG_DEBUG, "Expiring Blacklist (Older than $expireTime seconds)");

   # pull the current table for comparison (use whats loaded in pf now)
   `@{[$_PFCTL_CMD]} -t @{[PFLOG_BLOCK_TABLENAME]} -T show > @{[FILENAME_TMPBLACKLIST]}`;  # for comparison output

   # expire old entries and re-persist the table
   `@{[$_PFCTL_CMD]} -t @{[PFLOG_BLOCK_TABLENAME]} -T expire $expireTime >/dev/null 2>&1`;
   `@{[$_PFCTL_CMD]} -t @{[PFLOG_BLOCK_TABLENAME]} -T show > @{[FILENAME_BLACKLIST]}`;

   # compare the old and new...
   my @oldBlacklist = &loadXList(FILENAME_TMPBLACKLIST);
   if ($@) { syslog(LOG_ERR, "$@"); unlink(FILENAME_TMPBLACKLIST); return; }
   my @newBlacklist = &loadXList(FILENAME_BLACKLIST);
   if ($@) { syslog(LOG_ERR, "$@"); unlink(FILENAME_TMPBLACKLIST); return; }

   # report the difference at expiration
   foreach my $oldEntry (@oldBlacklist)
   {
      if (!&inList($oldEntry, \@newBlacklist))
      {
         syslog(LOG_INFO, "$oldEntry expired from blacklist");
      } 
   }

   unlink(FILENAME_TMPBLACKLIST);
}

sub loadBlacklistDB
{
   my $blacklistDB = $_[0];

   if ($blacklistDB && $blacklistDB ne '')
   {
      syslog(LOG_INFO, "Loading Blacklist DB into pf from $blacklistDB");
      `@{[$_PFCTL_CMD]} -t @{[PFLOG_BLOCK_TABLENAME]} -T replace -f $blacklistDB >/dev/null 2>&1`;

      # for display purposes - show the loaded blacklist
      my @curBlacklist = &loadXList(FILENAME_BLACKLIST);
      if ($@) { syslog(LOG_ERR, "$@"); return; }

      foreach my $entry (@curBlacklist)
      {
         syslog(LOG_DEBUG, "Loaded blacklist entry: $entry");
      }
   }
   else
   {
      syslog(LOG_ERR, 'No Blacklist DB file specified to load');
   }
}

sub loadXList
{
   my @ret;
   my $filename = $_[0];

   # read in the whitelist items - we don't ever want to add these
   open(XLIST, $filename) || die("Could not open $filename\n");
   while(my $line = <XLIST>)
   {
      # make sure we kill whitespace at the start and end of the string...
      chomp($line);
      $line =~ s/^\s+//;
      $line =~ s/\s+$//;
      # don't add blank lines...
      if ("$line" ne '')
      {
         # The '#' character at the /start/ of lines comments out said line
         if (substr($line, 0, 1) ne '#')
         {
            push(@ret, $line);
            syslog(LOG_DEBUG, "Found: $line in $filename list");
         }
         else
         {
            syslog(LOG_DEBUG, "Ignoring commented out line: $line");
         }
      }
   }
   close(XLIST);

   return @ret;
}

sub processAuthLog
{
   my @ret;
   my $line = $_[0];
   my $regexList = $_[1];
   
   # check the line against the "bad" log messages
   foreach my $secRegex (@{$regexList})
   {
      if ($line =~ /$secRegex/)
      {
         # validate the returned address (translate it if it's DNS)
         my $foundAddr = $1;
         chomp($foundAddr);
         syslog(LOG_DEBUG, "Found $foundAddr in processed log line");

         my ($addrErr, @addrInfoList) = getaddrinfo($foundAddr, '', {socktype => SOCK_RAW});
         if ($addrErr) { die("Unable to get address info for $foundAddr: $addrErr"); } 
         while(my $addrInfo = shift(@addrInfoList)) 
         {
            my ($nameErr, $ip) = getnameinfo($addrInfo->{addr}, NI_NUMERICHOST, NIx_NOSERV);
            if ($nameErr)
            {
               syslog(LOG_ERR, "Unable to resolve an address for $foundAddr: $nameErr");
               next;
            }
            push(@ret, $ip);
         }
      }
   }

   return @ret;
}

sub inRegexList
{
   my $item = $_[0];
   my $list = $_[1];
   
   foreach my $itemRegex (@{$list})
   {
      if ($item =~ /$itemRegex/)
      {
         syslog(LOG_DEBUG, "Regex Match: $item to $itemRegex");
         return 1;  # the item matches
      } 
   }

   return 0;
}

sub inList
{
   my $item = $_[0];
   my $list = $_[1];
   
   foreach my $curItem (@{$list})
   {
      if ("$item" eq "$curItem")
      {
         syslog(LOG_DEBUG, "Direct Match: $item to $curItem");
         return 1;  # the item matches
      } 
   }

   return 0;
}

sub readLinesNB 
{
   my @ret;
   my $filehandle = $_[0];
   my $buffer = $_[1];
   my $tmpBuf;

   # read as much as we can each time...
   while (sysread($filehandle, $tmpBuf, 1024)) 
   {
      # append it to the output buffer...
      $buffer .= $tmpBuf;
   }

   # make sure to pass back out our buffer...
   $_[1] = $buffer;

   # check for a newline at the end signifying we've got all we need
   my $lastChr = substr($buffer, length($buffer) - 1, 1);
   if ("$lastChr" eq "\n")
   {
      syslog(LOG_DEBUG, 'Finished reading buffer');
      @ret = split("\n", $buffer);
   }

   return @ret;
}

sub showHelp
{
   print("$_SCRIPT_NAME [-x|-expire <seconds>] [-l|-load <filename>]\n");
   print("              [-v|-version] [-h|-help]\n\n");
   print("-x | --expire <seconds>\tExpire (remove) blacklist entries from pf that have not\n");
   print("                        attempted access in specified <seconds>. Please note:\n");
   print("                          * 0 is ignored (same as not setting expire mode)\n");
   print("                          * -1 takes the default of @{[BLACKLIST_EXPIRE_TIME]} seconds\n");
   print("-l | --load <filename>\tLoad specified blacklist database into pf\n");
   print("-v | --version\t\tDisplay the version of $_SCRIPT_NAME_NOEXT and exit\n");
   print("-h | --help\t\tDisplay this message and exit\n\n");

   print("\nIf no paramters are specified $_SCRIPT_NAME_NOEXT runs in update mode which takes\ninput from STDIN and automatically adds entries to the blacklist that match the\nregular expressions found in @{[FILENAME_SECREGEX]}\n\nIf @{[FILENAME_SECREGEX]} does not exist, the following defaults are used:\n");

   foreach my $helpRegex (@{&DEFAULT_SECREGEX_LIST})
   {
      print("  * /$helpRegex/\n");
   }

   print("\nPlease note the following:\n");
   print("  * The various modes (load, expire, and update) are mutually exclusive.\n");
   print("  * There are no interactive messages. All information, errors, and so on are\n    logged via syslog to LOG_SECURITY.\n");
   print("\n");
}

MAIN:
{
   openlog($_SCRIPT_NAME_NOEXT, 'ndelay,pid', LOG_SECURITY);

   my $expireBL = 0;
   my $loadBL = 0;
   my $showVer = 0;
   my $showHelp = 0;
   GetOptions('x|expire=i' => \$expireBL, 'l|load=s' => \$loadBL, 'v|version' => \$showVer, 'h|help' => \$showHelp);

   # if show version or help - print out and exit
   if ($showVer || $showHelp)
   {
      if ($showVer)
      {
         print("$_SCRIPT_NAME_NOEXT version: @{[VERSION]}\n");
      }

      if ($showHelp)
      {
         &showHelp();
      }

      exit 0;
   }

   # make sure we can find pfctl
   if (!defined($_PFCTL_CMD) || defined($_PFCTL_CMD) && length($_PFCTL_CMD) <= 0)
   {
      syslog(LOG_ERR, 'Unable to locate pfctl');
      exit -1; 
   }

   # if we're in expire mode make sure we have a valid time...
   if ($expireBL <= -1)
   {
      $expireBL = BLACKLIST_EXPIRE_TIME;
   }

   # Only enter update mode if no other options are specified...
   if (!$expireBL && !$loadBL)
   { 
      my @whitelist;
      eval { @whitelist = &loadXList(FILENAME_WHITELIST) };  # Our manually maintained whitelist
      if ($@) { syslog(LOG_ERR, "Died: $@"); closelog(); exit 1; }
      my @curBlacklist;
      eval { @curBlacklist = &loadXList(FILENAME_BLACKLIST) }; # Our currently used blacklist - we update this directly using @blacklist
      if ($@) { syslog(LOG_ERR, "Died: $@"); closelog(); exit 2; }
      
      # Pull in the 'security' regex's (what to match against for blocking people)
      # if there is no user file - default to our internal constants...
      my @secRegexList;
      eval { @secRegexList = &loadXList(FILENAME_SECREGEX) }; # Our configured regex list
      if ($@) 
      {
         syslog(LOG_INFO, "No security regex list found at: @{[FILENAME_SECREGEX]} - using defaults"); 
         @secRegexList = (@{&DEFAULT_SECREGEX_LIST}); 
      }

      # setup our polling...
      STDIN->blocking(0);
      my $pollIO = IO::Poll->new();
      $pollIO->mask(\*STDIN => POLLIN);

      syslog(LOG_DEBUG, 'Reading from STDIN - polling until HUP');
      my $readBuf = '';  # used for handling non-blocking reads
      while ($pollIO->handles)
      {
         syslog(LOG_DEBUG, 'Entering poll');
         my $pollEvCnt = $pollIO->poll();
         if ($pollEvCnt > 0)
         {
            my $pollEvnts = $pollIO->events(\*STDIN);
            #check the handles if we woke up...
            if ($pollEvnts & POLLIN)
            {
               syslog(LOG_DEBUG, 'Notified of data to read');
               my $itemAdded = 0;
               my @lines = &readLinesNB(\*STDIN, $readBuf); 
               # make sure we have lines to process before attempting to do something!
               if (@lines && scalar(@lines) > 0)
               {
                  $readBuf = '';  # clear the read buffer...
                  foreach my $line (@lines)
                  {
                     chomp($line);
                     if ($line && "$line" ne '')
                     {
                        my @addrList;
                        eval { @addrList = &processAuthLog($line, \@secRegexList) };
                        if ($@) { syslog(LOG_ERR, "Unable to process auth.log message: $@"); next; }
                        foreach my $addr (@addrList)
                        {
                           # remove any entries from the black list that are on the whitelist
                           if (defined($addr) && "$addr" ne '')
                           {
                              if (&inRegexList($addr, \@whitelist) || &inList($addr, \@curBlacklist))
                              {
                                 syslog(LOG_DEBUG, "$addr is either already a blacklist item or matches something in the whitelist");
                              }
                              else
                              {
                                 syslog(LOG_INFO, "$addr will be added to the blacklist");
                                 push(@curBlacklist, $addr);
                                 $itemAdded = 1;
                              }
                           }
                        }
                     }
                  }
                  # if even one item was added lets commit the blacklist
                  if ($itemAdded)
                  {
                     &commitBlacklist(\@curBlacklist);
                  }
               }
               syslog(LOG_DEBUG, 'Done Reading');
            }
            if ($pollEvnts & POLLHUP)
            {
               syslog(LOG_DEBUG, 'HUP caught during poll');
               last;
            }
            if ($pollEvnts & POLLERR)
            {
               syslog(LOG_ERR, 'Caught POLLERR');
               closelog();
               exit 3;
            }
         }
      }
   }
   elsif ($loadBL && $loadBL ne '')
   { # load blacklist database from file mode
      &loadBlacklistDB($loadBL);
   }
   elsif ($expireBL != 0)
   { # blacklist maint mode
      &expireBlacklist($expireBL);
   }

   syslog(LOG_DEBUG, 'Ending');
   closelog();
   exit 0;
}
