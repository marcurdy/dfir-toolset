---
### Domain Attacks, Persistence, and Persistence
---

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
4 - Batch / Scheduled Task  
5 - Service  
7 - Unlock  
9 - New Credentials (RunAs)  
10 - RDP  
11 - Cached Interactive  
  
** LATERAL MOVEMENT  
4624 Network login  
4672 Admin login  
4688 Token elevation - Shows executable name  
5140 Network share  
Task / AT job - 106 (task sched) followed by 200 (task exe)  
201 Task finishes.  
141 Task removed else task remains to be viewed  
4634 Logoff  

### Domain Controller RDP/Remote access  
Little for security.evtx in DC due to wrapping log buffer  
#### TerminalServices Remote Connection Manager  
1149 - Remote RDP authentication  
#### TerminalServices Local Connection Manager  
21 - Successful login - could follow 1149  
23 - Logoff  
24 - Disconnect after logoff  
25 - Reconnect - could follow 1149  

####Persistence - Current Version Run key executes at login  
7045 - Service registered - ImagePath for executable in unusual path  
  
####Regaining User account  
* Autorun Malware to regain user access  
   Autoruns will show unsigned code as red (vbscript)  
     Malicious code could be appended to existing vbs's  
     Yellow lines are where files aren't found  
* Create registry based backdoors  
   False startups links call [power]shellcode dropper  
1. Creating a Domain Account  
   net user USER PASSWD /add /domain  
   net group "Domain Admins" user /add /domain  
   4720 User account created  
   4722 Enabled user account  
   4724 Reset account password  
   4728 Member added to security enabled global group Domain Admin  
   4737 Security enabled global group was changed  
2. Skeleton Key Patch  
   Use mimikatz to run (AV could catch binary)  
   New LSA security provider added to (LSASS)  
   net user \\XXX\c$ /user:domain\admin mimikatz  
   Domain Admin abilities granted  
   4673 A Privileged service was called - Register logon process  
     Occurs during reboot  
3. Creating Golden Tickets  
   Golden Ticket - Forged TGT (Ticket to get tickets)  
   Silver Ticket - Forged TGS (Ticket Granting Service)  
   Tickets allow to connect to LDAP service and perform DCSync to pull passwords  
   Overpass-the-Hash - Use kerberos ticket to change a user's password which is more powerful than PTH  
   Hacker needs to be NT Authority Systems then scrapes krbtgt hash  
   Ticket does not register with domain ctrl for 20 minutes  
   Can use kerberroast for offline cracking of service tickets  
* No admin rights  
* No traffic sent to target  
* Get service tickets to each SPN  
* Mimikatz to save svc ticket to a file  
* Kerberoast brute forces the ticket  
   Log event is not unique. Only found by error - casing issues, wrong values  
   IDS signature involving ARCFOUR-HMAC-MD5 NTLM enc type  
   To cleanup, rotate password of krbtkt twice.  Win2008+ require all in domain to reboot.  
4. Tamper with SID History  
   Requires mimikatz. No sign user has secondary SID.  
   4765 User Acct Mgmt - Sid history was added to an account  
5. Tamper with AD DACL's  
   AD Objects have ACL's like files.  Not exposed in UI.   
   VB is required to modify AD Objects  
   Add user to a built-in object group like Terminal Services  
   Modify AdminSDHolder ACL so it will replace built-in within an hour  
   Modify the built-in service's ACL and the new AdminSDHolder will replace it  
   4735 Security Enabled Local Group changed (the built-in)  
   4737 Security Enabled Global group was changed  
   5136 Directory Service changes - DS object was modified - Value deleted/added  
   Changing DACL requires VB script  
  
#### Owning Domain Controller  
- Get Access to the NTDS.dit file and extract data  
- Dump Credentials on DC (local or remote)  
  + Mimikatz, Invoke-Mimikatz, Mimikatz DCSync  
  
#### Defense:   
MS LAPS - automatic local admin pw change - random for each pw  
Enable proper logging plus command-shell and power shell logging  
Forged Kerberos Tickets: Potential domain field anomolies in events  
DC Silver Tickets: Change acct passwords after breach  
AdminSDHolder: Check Object Permissions  
DCSync: IDS Sig of "DRSUAPI" or "DsGetNCCChanges request" where src != DC IP  
DSRM v2: Change DSRM PW regularly & monitor reg key & DSRM events  
  
#### Powershell attack detection  
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
  
  Current Windows Event ID	Legacy Windows Event ID	Potential Criticality	Event Summary
4618	N/A	High	A monitored security event pattern has occurred.
4649	N/A	High	A replay attack was detected. May be a harmless false positive due to misconfiguration error. This event indicates that a Kerberos replay attack was detected- a request was received twice with identical information. This condition could be caused by network misconfiguration.  
  
++ General include for SIEM's
  
Event ID | Legacy ID | Severity | Description  
-------- | --------- | -------- | -----------
4718 | N/A | Low | System security access was removed from an account
4719 | 612 | High | System audit policy was changed.
4730 |  |  | A security-enabled global group was deleted.
4737 |  |  | A security-enabled global group was changed.
4739 |  |  | Domain Policy was changed.
4755 |  |  | A security-enabled universal group was changed.
4758 |  |  | A security-enabled universal group was deleted.
4765 | N/A | High | SID History was added to an account.
4766 | N/A | High | An attempt to add SID History to an account failed.
4794 | N/A | High | An attempt was made to set the Directory Services Restore Mode.
4897 | 801 | High | Role separation enabled:
4950 |  |  | A Windows Firewall setting has changed.
4964 | N/A | High | Special groups have been assigned to a new logon.
5124 | N/A | High | A security setting was updated on the OCSP Responder Service
N/A | 550 | Medium to High | Possible denial-of-service (DoS) attack
1102 | 517 | Medium to High | The audit log was cleared
4621 | N/A | Medium | Administrator recovered system from CrashOnAuditFail. Users who are not administrators will now be allowed to log on. Some auditable activity might not have been recorded.
4675 | N/A | Medium | SIDs were filtered.
4692 | N/A | Medium | Backup of data protection master key was attempted.
4693 | N/A | Medium | Recovery of data protection master key was attempted.
4706 | 610 | Medium | A new trust was created to a domain.
4713 | 617 | Medium | Kerberos policy was changed.
4714 | 618 | Medium | Encrypted data recovery policy was changed.
4715 | N/A | Medium | The audit policy (SACL) on an object was changed.
4716 | 620 | Medium | Trusted domain information was modified.
4724 | 628 | Medium | An attempt was made to reset an account’s password.
4727 | 631 | Medium | A security-enabled global group was created.
4735 | 639 | Medium | A security-enabled local group was changed.
4737 | 641 | Medium | A security-enabled global group was changed.
4739 | 643 | Medium | Domain Policy was changed.
4754 | 658 | Medium | A security-enabled universal group was created.
4755 | 659 | Medium | A security-enabled universal group was changed.
4764 | 667 | Medium | A security-disabled group was deleted
4764 | 668 | Medium | A group’s type was changed.
4780 | 684 | Medium | The ACL was set on accounts which are members of administrators groups.
4816 | N/A | Medium | RPC detected an integrity violation while decrypting an incoming message.
4865 | N/A | Medium | A trusted forest information entry was added.
4866 | N/A | Medium | A trusted forest information entry was removed.
4867 | N/A | Medium | A trusted forest information entry was modified.
4868 | 772 | Medium | The certificate manager denied a pending certificate request.
4870 | 774 | Medium | Certificate Services revoked a certificate.
4882 | 786 | Medium | The security permissions for Certificate Services changed.
4885 | 789 | Medium | The audit filter for Certificate Services changed.
4890 | 794 | Medium | The certificate manager settings for Certificate Services changed.
4892 | 796 | Medium | A property of Certificate Services changed.
4896 | 800 | Medium | One or more rows have been deleted from the certificate database.
4906 | N/A | Medium | The CrashOnAuditFail value has changed.
4907 | N/A | Medium | Auditing settings on object were changed.
4908 | N/A | Medium | Special Groups Logon table modified.
4912 | 807 | Medium | Per User Audit Policy was changed.
4960 | N/A | Medium | "IPsec dropped an inbound packet that failed an integrity check. If this problem persists |  it could indicate a network issue or that packets are being modified in transit to this computer. Verify that the packets sent from the remote computer are the same as those received by this computer. This error might also indicate interoperability problems with other IPsec implementations."
4961 | N/A | Medium | "IPsec dropped an inbound packet that failed a replay check. If this problem persists |  it could indicate a replay attack against this computer."
4962 | N/A | Medium | IPsec dropped an inbound packet that failed a replay check. The inbound packet had too low a sequence number to ensure it was not a replay.
4963 | N/A | Medium | IPsec dropped an inbound clear text packet that should have been secured. This is usually due to the remote computer changing its IPsec policy without informing this computer. This could also be a spoofing attack attempt.
4965 | N/A | Medium | "IPsec received a packet from a remote computer with an incorrect Security Parameter Index (SPI). This is usually caused by malfunctioning hardware that is corrupting packets. If these errors persist |  verify that the packets sent from the remote computer are the same as those received by this computer. This error may also indicate interoperability problems with other IPsec implementations. In that case |  if connectivity is not impeded |  then these events can be ignored."
4976 | N/A | Medium | "During Main Mode negotiation |  IPsec received an invalid negotiation packet. If this problem persists |  it could indicate a network issue or an attempt to modify or replay this negotiation."
4977 | N/A | Medium | "During Quick Mode negotiation |  IPsec received an invalid negotiation packet. If this problem persists |  it could indicate a network issue or an attempt to modify or replay this negotiation."
4978 | N/A | Medium | "During Extended Mode negotiation |  IPsec received an invalid negotiation packet. If this problem persists |  it could indicate a network issue or an attempt to modify or replay this negotiation."
4983 | N/A | Medium | An IPsec Extended Mode negotiation failed. The corresponding Main Mode security association has been deleted.
4984 | N/A | Medium | An IPsec Extended Mode negotiation failed. The corresponding Main Mode security association has been deleted.
5027 | N/A | Medium | The Windows Firewall Service was unable to retrieve the security policy from the local storage. The service will continue enforcing the current policy.
5028 | N/A | Medium | The Windows Firewall Service was unable to parse the new security policy. The service will continue with currently enforced policy.
5029 | N/A | Medium | The Windows Firewall Service failed to initialize the driver. The service will continue to enforce the current policy.
5030 | N/A | Medium | The Windows Firewall Service failed to start.
5035 | N/A | Medium | The Windows Firewall Driver failed to start.
5037 | N/A | Medium | The Windows Firewall Driver detected critical runtime error. Terminating.
5038 | N/A | Medium | Code integrity determined that the image hash of a file is not valid. The file could be corrupt due to unauthorized modification or the invalid hash could indicate a potential disk device error.
5120 | N/A | Medium | OCSP Responder Service Started
5121 | N/A | Medium | OCSP Responder Service Stopped
5122 | N/A | Medium | A configuration entry changed in OCSP Responder Service
5123 | N/A | Medium | A configuration entry changed in OCSP Responder Service
5376 | N/A | Medium | Credential Manager credentials were backed up.
5377 | N/A | Medium | Credential Manager credentials were restored from a backup.
5453 | N/A | Medium | An IPsec negotiation with a remote computer failed because the IKE and AuthIP IPsec Keying Modules (IKEEXT) service is not started.
5480 | N/A | Medium | IPsec Services failed to get the complete list of network interfaces on the computer. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.
5483 | N/A | Medium | IPsec Services failed to initialize RPC server. IPsec Services could not be started.
5484 | N/A | Medium | IPsec Services has experienced a critical failure and has been shut down. The shutdown of IPsec Services can put the computer at greater risk of network attack or expose the computer to potential security risks.
5485 | N/A | Medium | IPsec Services failed to process some IPsec filters on a plug-and-play event for network interfaces. This poses a potential security risk because some of the network interfaces may not get the protection provided by the applied IPsec filters. Use the IP Security Monitor snap-in to diagnose the problem.
6145 | N/A | Medium | One or more errors occurred while processing security policy in the Group Policy objects.
6273 | N/A | Medium | Network Policy Server denied access to a user.
6274 | N/A | Medium | Network Policy Server discarded the request for a user.
6275 | N/A | Medium | Network Policy Server discarded the accounting request for a user.
6276 | N/A | Medium | Network Policy Server quarantined a user.
6277 | N/A | Medium | Network Policy Server granted access to a user but put it on probation because the host did not meet the defined health policy.
6278 | N/A | Medium | Network Policy Server granted full access to a user because the host met the defined health policy.
6279 | N/A | Medium | Network Policy Server locked the user account due to repeated failed authentication attempts.
6280 | N/A | Medium | Network Policy Server unlocked the user account.
- | 640 | Medium | General account database changed
- | 619 | Medium | Quality of Service Policy changed
24586 | N/A | Medium | An error was encountered converting volume
24592 | N/A | Medium | An attempt to automatically restart conversion on volume %2 failed.
24593 | N/A | Medium | "Metadata write: Volume %2 returning errors while trying to modify metadata. If failures continue |  decrypt volume"
24594 | N/A | Medium | "Metadata rebuild: An attempt to write a copy of metadata on volume %2 failed and may appear as disk corruption. If failures continue |  decrypt volume."


