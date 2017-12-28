Detecting Lateral Movement in Windows

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
  
Technique 2: Event Log Analysis  
  
* Account Misuse
  * Find use of mapped admin shares
    * Shellbags or ntuser.dat's MountPoints2 for use of C$, ADMIN$, IPC$
    * Staging malware or accessing sensitive files
    * Vista or later requires domain admin or built-in admin rights
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
  
4624 - Successful Logon  
4625 - Failed Logon  
4634/4647 Successful Logoff  
4648 - Logon using RunAs credentials  
4672 - Admin login / Special login  
  
Terminal services log id 21,24,25  
  
4776 - On DC, success/fail during hash authentication  
  
5140 - Network share was accessed  
5145 - Shared object access (detailed within)  
  
201 - Schtask executed  
4698,4699,4702, - Schtask created, deleted, updated  
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
4697 - service installed on system  
  
1033/1034 - App install/remove  
11707/11708 - Install success/fail  
11724 - Uninstall completely removed  
  
4688 - Process created (if process tracking on, turn on command-line auditing)  
  
1102 - Audit log cleared (Security)  
104 - Audit log cleared (System)  
  
Technique 3: Signs of Environment Intelligence Gathering
* Look for the use of built-in tools and determine the TTP
at.exe  
bitsadmin.exe  
cmd.exe  
csvde.exe  
dcdiag.exe  
dsquery.exe  
ftp.exe  
ldifde.exe  
makecab.exe  
nbtstat.exe  
net1.exe  
net.exe  
netstat.exe (netstat -ano)  
nltest.exe  
nslookup.exe  
ntdsutil.exe  
ping.exe (ping -A)  
powershell.exe  
procdump.exe  
psloggedon.exe  
query.exe  
rar.exe  
reg.exe  
regsvr32.exe  
route.exe  
sc.exe  
schtasks.exe  
systeminfo.exe  
taskkill.exe (taskkill /f /im <process_name> or by PID.)  
tasklist.exe (tasklist /v)  
vssadmin.exe  
whoami.exe  
wmic.exe  
xcopy.exe  
  
Sources:  
1) JPCert Tool Analysis Report  
2) SANS 508  
3) SANS Finding Evil in the Whitelist  
