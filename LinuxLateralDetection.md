Checking for Lateral Movement on Linux

* Determine timeframe of event  
  * External source  
  * Local log entries
  * Metadata change on file of interest
    * Check if atime is crippled with noatime, nodiratime, or relatime using “mount”
      *	Access and Modify times are easily altered
      *	Change times (metadata e.g. chown) are not easily timestomped
* Examine logins around the time of event 
  * Check the syslog configuration for log filenames. Below is typical.
    * /var/log/secure* or /var/log/auth*
    * /var/log/messages* or /var/log/syslog*
    * /var/log/*
  * Logins housed in a DB read with “last –f <filename>”
  * Current logins: /var/run/wtmp  
  * Historical logins/logouts: /var/log/utmp  
  * Failed logins: /var/log/btmp 
* Check bash history where bash is the user’s shell (ksh, csh differ)
  *	Assuming no timestamps are in USERHOME/.bash_history, you can do temporal searches based on the bash_history 
    last modify times knowing that was the most recent logout time.  
  *	Never assume bash_history is in execution order.  Two shells running commands at the same time will dump each
    of their history blocks only when that shell terminates.
  *	The file can be hand edited or removed by the user
  *	Suggest that the customer deploys bash history time stamps.
* Check timestamps within home directories
  *	Access time updates for .bash* or .profile can show login 
  *	Access time on .ssh/known_hosts shows ssh client outbound attempt
  *	Access time on .ssh/authorized_keys shows ssh inbound attempt as this HOMEDIR user
* Examine sudo logs around the time of the event (check syslog config for path)
  * Typically found within /var/log/secure* or /var/log/auth*
  * sudo rules are typically in /etc/sudoers and /etc/sudoers.d/*
  * sudo can run commands as root or as other users
* Examine sshd sessions around time of event  
  * Current logs: /var/log/secure  or /var/log/auth
  * Historical logs: /var/log/secure-YYYYMMDD 
* Check application logs
  * Typically do not log through syslog if the software was not installed by the package manager
  * Can exist anywhere on the system
  * LLR collections *.log off disk into otheroslogs.tar.gz but would skip *.log.gz
* Examine audit logs
  * /var/log/audit.log if installed and running
  * Contents are dependent on administrator’s custom configuration
  * ausearch is powerful for searching audit.log
  * aureport generates a report on audit.log
* If the image or access to the filesystem is available, use the Sleuthkit to make a timeline
  * fls –rd / > filedump.txt
  * mactime –b filedump.txt > filedump_mac.txt
