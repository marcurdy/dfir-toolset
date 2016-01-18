#################################################
** Domain Attacks, Persistence, and Persistence
#################################################

PowerSploit
* Invoke-Shellcode/TokenManipulation/Mimikatz
* Get-GPPPassword
* Add-Persistence

Empire:
* Pure PowerShell agent with secure comms
* Run PS code with PowerShell.exe
* Wraps func of most popular attack tools ex. Macros, DLL, HDA
* Injects into processes
* Leverages Python

Scan Domains in environments
Finding Privileged Accounts recursively finds:
* Domain Admins, Administrators, RODC Denied Replication GRoups
Enumerate Trusts and Contact Objects in Forest to find partner orgs

SPN Scanning Service Discovery without network port scanning
* Service Principle Name is required for Kerberos to function
* User requests service which requires kerberos service ticket
    Includes SQL, RDP, WinRM, FIM, SCCM

Event Log Explorer FSPro Labs

Logon Type
2 - Interactive
3 - Remote
10 - RDP

** LATERAL MOVEMENT
4624 Network login
4672 Admin login
4688 Token elevation - Shows executable name
5140 Network share
Task / AT job - 106 (task sched) followed by 200 (task exe)
201 Task finishes.
141 Task removed else task remains to be viewed
4634 Logoff

** Domain Controller RDP/Remote access
Little for security.evtx in DC due to wrapping log buffer
*TerminalServices Remote Connection Manager
1149 - Remote RDP authentication
** TerminalServices Local Connection Manager
21 - Successful login - could follow 1149
23 - Logoff
24 - Disconnect after logoff
25 - Reconnect - could follow 1149

Persistence - Current Version Run key executes at login
7045 - Service registered - ImagePath for executable in unusual path

Regaining User account
* Autorun Malware to regain user access
   Autoruns will show unsigned code as red (vbscript)
     Malicious code could be appended to existing vbs's
     Yellow lines are where files aren't found
* Create registry based backdoors
   False startups links call [power]shellcode dropper
1) Creating a Domain Account
   net user USER PASSWD /add /domain
   net group "Domain Admins" user /add /domain
   4720 User account created
   4722 Enabled user account
   4724 Reset account password
   4728 Member added to security enabled global group Domain Admin
   4737 Security enabled global group was changed
2) Skeleton Key Patch
   Use mimikatz to run (AV could catch binary)
   New LSA security provider added to (LSASS)
   net user \\XXX\c$ /user:domain\admin mimikatz
   Domain Admin abilities granted
   4673 A Privileged service was called - Register logon process
     Occurs during reboot
3) Creating Golden Tickets
   Golden Ticket - Forged TGT (Ticket to get tickets)
   Silver Ticket - Forged TGS (Ticket Granting Service)
   Tickets allow to connect to LDAP service and perform DCSync to pull passwords
   Overpass-the-Hash - Use kerberos ticket to change a user's password which is more powerful than PTH
   Hacker needs to be NT Authority Systems then scrapes krbtgt hash
   Ticket does not register with domain ctrl for 20 minutes
   Can use kerberroast for offline cracking of service tickets
     - No admin rights
     - No traffic sent to target
     - Get service tickets to each SPN
     - Mimikatz to save svc ticket to a file
     - Kerberoast brute forces the ticket
   Log event is not unique. Only found by error - casing issues, wrong values
   IDS signature involving ARCFOUR-HMAC-MD5 NTLM enc type
   To cleanup, rotate password of krbtkt twice.  Win2008+ require all in domain
     to reboot.
4) Tamper with SID History
   Requires mimikatz. No sign user has secondary SID.
   4765 User Acct Mgmt - Sid history was added to an account
5) Tamper with AD DACL's
   AD Objects have ACL's like files.  Not exposed in UI. 
   VB is required to modify AD Objects
   Add user to a built-in object group like Terminal Services
   Modify AdminSDHolder ACL so it will replace built-in within an hour
   Modify the built-in service's ACL and the new AdminSDHolder will replace it
   4735 Security Enabled Local Group changed (the built-in)
   4737 Security Enabled Global group was changed
   5136 Directory Service changes - DS object was modified - Value deleted/added
   Changing DACL requires VB script

Owning Domain Controller
- Get Access to the NTDS.dit file and extract data
- Dump Credentials on DC (local or remote)
  + Mimikatz, Invoke-Mimikatz, Mimikatz DCSync

Defense: 
MS LAPS - automatic local admin pw change - random for each pw
Enable proper logging plus command-shell and power shell logging
Forged Kerberos Tickets: Potential domain field anomolies in events
DC Silver Tickets: Change acct passwords after breach
AdminSDHolder: Check Object Permissions
DCSync: IDS Sig of "DRSUAPI" or "DsGetNCCChanges request" where src != DC IP
DSRM v2: Change DSRM PW regularly & monitor reg key & DSRM events

Powershell attack detection
Log all powershell activity
Interesting activity
  -Downloads via .NET
  -Invoke-Expression (& derivatives: "iex")
  -"EncodedCommand" ("-enc") & "Bypass"
  -BITS activity
  -Scheduled Task creation/deletion
  -PowerShell remoting
Limit & Track Powershell remoting (configure WinRM to certain domains)
Audit & Meter PowerShell usage

Invoke-Mimikatz even log keywords:
  "System.Reflection.AssemblyName"
  "System.Reflection.Emit.AssemblyBuilderAccess"
  "System.Runtime.InteropServices.MarshalAsATtribute"
  "TOKEN_PRIVILEGES"
  "SE_PRIVILEGE_ENABLED"
Invoke-TokenManipulation
  "TOKEN_IMPERSONATE"
  "TOKEN_DUPLICATE"
  "TOKEN_ADJUST_PRIVILEGES"
Invoke-CredentialInjection:
  "TOKEN_PRIVILEGES"
  "GetDelegateForFunctionPointer"
Invoke-DLLInjection
  "System.Reflection.AssemblyName"
  "System.Reflection.Emit.AssemblyBuilderAccess"
Invote-Shellcode
  "System.Reflection.AssemblyName"
  "System.Reflection.Emit.AssemblyBuilderAccess"
  "System.MulticastDelegate"
  "System.Reflection.CallingConventions"
Get-GPPPassword (Group Policy Pref Passwords)
  "System.Security.Cryptography.AesCryptoServiceProvider"
  "0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4"
  "Groups.UserProperties.cpassword"
  "ScheduledTasks.Task.Properties.cpassword"
Out-MiniDump
  "System.Management.Automation.WindowsErrorReporting"
  "MiniDumpWriteDump"

Detect Kerberos exploit
  MS14-068 - IDS Signature for Kerberos AS-REQ & TGS-REQ w "Include PAC: False"
Group Policy Pref - MS Goof exposing private key
  Install KB2962486 and delete existing GPP xml files in SYSVOL containing pw's
  No passwords in SYSVOL!!
Set GPO to prevent local accounts from connecting over network to computers
  KB2871997
Implement RDP Restricted Admin Mode
  Removes Credentials at Logoff
  Removes clear-text passwords from memory
   -monitor HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest=0
  Win7/Win2k8R2: KB2984972 / KB2984976 / KB2984981
  Win8/Win 2012: KB2973501
