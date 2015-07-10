# pflogblock

As many of have experienced, having a server exposed to the internet can be at least annoying and sometimes just plain dangerous if not properly secured.

This project started off as a way to dynamically block people who were trying to brute-force ssh on my server by way
of syslog passing auth events to it and, based on configurable regexs, pull out offending IPs and block them for a 
configurable amount of time.

Two last things to note:
 1. I'm a C/C++ developer writing perl so my perl looks like C code...
 2. As I'm mostly a FreeBSD guy, I've written this script with that in mind.  It may be portable to Linux or another system
but that is not my primary goal at the moment.  This is simply a small, side project I use as an ocassional distraction.

# Basic Setup

To get going with pflogblock, I recommend the following basic configuration items:
 * The following dependencies are required for pflogblock to run:
  * A compatible syslog that is able to pipe messages to external applications
    * The default FreeBSD syslog is capable of this
  * A compatible firewall
    * Currently, only pf is supported - pflogblock uses pfctl directly
  * perl 5.18 or above
    * Currently building/testing with perl 5.20
  * perl File::Which (CPAN)
    * Can be found in FreeBSD ports: sysutils/p5-File-Which
 * Place pflogblock.pl in a location where it will be run by root
  * Ownership should be: root:wheel
  * Permissions should be: -rwxrx---- (750)
 * Setup cronjobs to automatically load the last known blacklist and expire IPs off of the blacklist
  * Example cronjobs for this can be found in this source tree: https://github.com/newodahs/pflogblock/blob/master/fbsd/root.crontab
 * Setup whitelist table and blacklist regex configuration files
  * Example blacklist regex configuration can be found in this source tree: https://github.com/newodahs/pflogblock/blob/master/fbsd/usr/local/etc/pflogblock_regex.conf
  * Example whitelist table can be found in this source tree: https://github.com/newodahs/pflogblock/blob/master/fbsd/var/db/pflogblock_whitelist
    * The whitelist is very important - you don't want to lock yourself out on accident!
 * Setup syslog to pipe log messages from desired log file for processing
  * Example assumes the auth.log (which is likely the most appropriate)
  * Example syslog configuration lines can be found in this source tree: https://github.com/newodahs/pflogblock/blob/master/fbsd/etc/syslog.conf
  
  
# Advanced Configuration

Once you have everything up and working, feel free to mess around with the configuration a bit.  As I noted in the
first few lines of this file, I originally wrote this with an eye toward stopping brute-force ssh attempts.  It
should be possible, however, to pass just about any log messages through this script and take action to block any
address found.

Keep in mind, if you're writing your own custom regexs to take action on: pflogblock will only take action on the
first capture group in the regex.  Try to keep your captures to a single one for now - this may change in the future.

# Release Notes

July-2015
First revision of this script.  Base functionality is as follows:
 * Accepts piped log messages from syslog for processing
  * See: https://www.freebsd.org/cgi/man.cgi?query=syslog.conf(5) for more information
 * Setup to be syslog smart - once run by syslog it will stay active while the pipe is open
  * This keeps the script at the ready while honoring documented behavior for this type of integration
 * Ships with two default blacklist regexs to determine bad behavior with
  * Default blacklist regexs may be overriden with: /usr/local/etc/pflogblock_regex.conf
 * Allows specification of a whitelist (addresses that will never be blacklisted)
  * Whitelist location is /var/db/pflogblock_whitelist;
 * Resolves DNS to IPv4 or IPv6 for blocking
  * Blocks /all/ associated address to resolved DNS entries (not just the first one)
 * Logs out its own activities to syslog (LOG_SECURITY)
