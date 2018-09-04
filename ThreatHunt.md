[Non-OS Threat Detection](#non-os-specific-threat-detection)
[Windows Threat Hunting](#detecting-lateral-movement-in-windows)
[Linux Threat Hunting](#detecting-lateral-movement-in-linux)

#Non-OS Specific threat detection

Namespace Collisions
* Internal domain names are not controlled externally
* Create a list of domains from DNS used by the clients for the org. Who owns their IP resolution?
* Search if wpad.dat reaches external organizations
* Search for domains outside com, net, org, gov, mil, edu

DNS/Proxy 
* Search for destinations of dynamic dns domains
* High volumes of NXDOMAIN errors could signify use of a domain generating algorithm (DGA)
* Search for typos of domains being accessed e.g. dnstwist
* Malicious domains often are set as uncategorized by proxies
  * Unsolicited outbound communication to the hostile domain with no referrer
  * Reputation of the domain
* Consistent and reoccurring HTTP PUT
* Suspicious user-agents such as powershell especially PUT
  
Source: Sqrrl Huntpedia PDF  
  
#Detecting Lateral Movement in Windows
  
Detailed tools execution and the artifacts they create at https://jpcertcc.github.io/ToolAnalysisResultSheet/
* Command Execution
* Password and hash dumps
* Remote login
* PTH, PTT
* Privilege Escalation
* Capturing domain rights
* Local user/group changes
* File sharing
* Evidence deletion
* Information Collection  
  
__My techniques collected outside of the JP CERT website are as follows.__  
  
In most scenarios, use VSSAdmin if your data source does not contain your date range  
  
Technique 1: Remote Code Execution  
  
* Remote code execution
  * Execution of PsExec
    * psexec sends over IPC$. stdout, stderr sent over SMB 
    * Initiated with a 5140/5145 with IPC$ to test permission
    * mounts hidden ADMIN$, copies psexesvc.exe remotely, starts the service and exec command
	  * Named pipes used to communicate
	  * artifacts: app exec, pushed binaries, user profile creation w/o -e
	  * Registry: service registration and EulaAccepted  
  
  * Windows Remote Mgmt Tools for local or remote
    * sc.exe, schtasks.exe, at.exe, reg.exe, winrs.exe (remote command)
      * Found in authentications, services system log, task scheduler logs, CL auditing
      * Scheduled tasks
      * AT -> \Windows\System32\Tasks  schtasks are XML
      * See evtlog Task Scheduler\Operational (eventid below)
      * schtasks entry injects remote host/user as Author
  
  * Powershell Remoting / WMIC
    * Usage = wmic /node:host /user:user process call create "command"
    * Other powershell procedures = Invoke-WmiMethod, Invoke-Command, Enter-PSSession
    * Detect execution: wmiprvse.exe, powershell.exe, wsmprovhost.exe
    * Must turn on command line auditing for detection 
  
  * RDP/VPN Activity
    * Event logs record inbound RDP activity
    * Registry contains recent RDP client activity
    
  * Samba activity
    * In a domain, look for client's in a workgroups accessing Samba 
  
Technique 2: Event Log Analysis  
  
* Account Misuse
  * Find use of mapped admin shares
    * Shellbags or ntuser.dat's MountPoints2 for use of C$, ADMIN$, 
    $
    * Staging malware or accessing sensitive files
    * Vista or later requires domain 
    or built-in admin rights
  * Logon using RunAs (eventid below)
  * Track admin activity where special logon 4672 == an administrative account  
  * Domain Admin anomalies
  * New accounts created locally or administrative rights granted to existing (eventid below)  
  * Workstation to workstation connections based off hostname/ip lookups
  * Pass the Hash (PTH): 4776 from local account with 4624 showing network logon
  * Kerberos TGT/TS
    * Use klist.exe to list session details and determine if time is > MaxTicketAge
    * Domain field in 4624, 4634, 4672 should be the shortname
  * Account logs into many remote hosts in too short a time
  
* Suspicious Services
  * Locate services run outside of service accounts	
  * Reference an executable in a non-standard directory
  * Blank fields which normally hold values
  * New service installed (eventid below)
  * Set to a stopped state (eventid below)
  * Service crashed (eventid below)
  * Setup with a Service Failure Recovery binary to run if service fails
  
* Crashes and security alerts
* Cleared out audit logs (eventid below)
* Detect ticket reuse
  * See JPCert URL linked at the top

* Common EventID Meanings  
  
528,4624 - Successful Logon  
529,4625 - Failed Logon  
4634,4647 Successful Logoff  
552,4648 - Logon using RunAs credentials  
4672 - Admin login / Special login  
  
Terminal services log id 21,24,25  
  
4776 - On DC, success/fail during hash authentication  
  
5140 - Network share was accessed  
5145 - Shared object access (detailed within)  
  
201 - Schtask executed  
602,4698,4699,4702, - Schtask created, deleted, updated  
4700/4701 - Schtask enabled/disabled  
  
4720 - Account created  
4762 - Assignment of Administrator Rights  
4768/4769 - Domain account authentication  
4771 - Logon Error for Kerberos (very detailed reason)  
4778/4779 - Session create/close (RDP)  
  
7034 - Service crashed  
7035 - Service sent start/stop  
7036 - Service started/stopped  
7040 - Start type changed  
7045 - service installed first time (win2008R2)  
601,4697 - service installed on system  
  
1033/1034 - App install/remove  
11707/11708 - Install success/fail  
11724 - Uninstall completely removed  
  
4688 - Process created (if process tracking on, turn on command-line auditing)  
  
1102 - Audit log cleared (Security)  
104 - Audit log cleared (System)  
  
Technique 3: Signs of Environment Intelligence Gathering
* Look for the use of built-in tools and determine the TTP  
at  
bitsadmin  
cmd  
control  
csvde  
dcdiag  
dsquery  
ftp  
ldifde  
makecab  
nbtstat  
net1  
net  
netsh  
netstat (netstat -ano)  
nltest  
nslookup  
ntdsutil  
ping (ping -A)  
powershell  
procdump  
psloggedon  
query  
rar  
reg  
regsvr32  
route  
sc  
schtasks  
systeminfo  
taskkill (taskkill /f /im <process_name> or by PID.)  
tasklist (tasklist /v)  
vssadmin  
whoami  
winword /L
wmic  
xcopy  

Technique 2: Network Event Detection using Bro, netflow, firewall, and proxy logs
* Port number does not match the protocol contained within
  * Search protocol metadata, exclude matched protocols, and search
  * Search for ports used that aren't registered with IANA
  * Encryption on typically non-encrypted port numbers
  * Common application protocol indicators include
    * Domain, URL, User-Agent string
    * x.509 Certificate Subject and Issuer
    * Email address

Sources:  
1) JPCert Tool Analysis Report  
2) SANS 508  
3) SANS Finding Evil in the Whitelist  


#Detecting Lateral Movement in Linux

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
* Look for signs of an adversary "Living off the land"
  * arp nmap ping who whoami traceroute nslookup dig telnet netstat lsof host ss route	macchange ip tcpkill id getent wget curl shred touch openssl chattr gcc history iptables xwd
