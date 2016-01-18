--- 
## Logging Methodologies
---

### AUTHENTICATION AND AUTHORIZATION REPORTS  
  All login failures and successes by user, system, business unit  
  Login attempts (successes, failures) to disabled/service/non-existing/default/suspended accounts  
  All logins after office hours / “off” hours  
  Users failing to authentication by count of unique systems they tried  
  VPN authentication and other remote access logins (success, failure)  
  Privileged account access (successes, failures)  
  Multiple login failures followed by success by same account  
  
### Change Reports - Tripwire/Audit detected configuration changes  
  Additions/changes/deletions to users, groups  
  Additions of accounts to administrator / privileged groups  
  Password changes and resets—by users and by admins to users  
  Additions/changes/deletions to network services  
  Changes to system files—binaries, configurations  
  Changes to other key files  
  Changes in file access permissions  
  Changes to sensitive files  
  
### Network Activity Reports  
  All outbound connections from internal and DMZ systems by system, connection count, user, bandwidth, count of unique destinations  
  All outbound connections from internal and DMZ systems during “off” hours  
  Top largest file transfers (inbound, outbound) OR Top largest sessions by bytes transferred  
  Web file uploads to external sites  
  All file downloads with by content type (exe, dll, scr, upx, etc.) and protocol (HTTP, IM, etc.)  
  Internal systems using many different protocols/ports  
  Top internal systems as sources of multiple types of NIDS, NIPS or WAF Alerts  
  VPN network activity by username, total session bytes, count of sessions, usage of internal resources  
  P2P use by internal systems  
  Wireless network activity  
  Log volume trend over days  
  
### Resource Access Reports  
  Access to resources on critical systems after office hours / “off” hours  
  Top internal users blocked by proxy from accessing prohibited sites, malware sources, etc.  
  File, network share, or resource access (success, failure)  
  Top database users  
  Summary of query types  
  All privileged database user access  
  All users executing INSERT, DELETE database commands  
  
### Malware Activity Reports  
  Malware detection trends with outcomes: a basic report with a summary or a trend of malicious software detection, also showing the system and the outcome   
  Detect-only events from anti-virus tools  
  All anti-virus protection failures  
  Internal connections to known malware IP addresses  
  Least common malware types  
  
### Critical Errors and Failures Reports  
  Critical errors by system, application, business unit: various error messages (especially for the first time) could present early indication of malicious activities  
  System and application crashes, shutdowns, restarts  
  Backup failures are critical events affecting business continuity and possibly regulatory compliance, unauthorized backups (failed) may be triggered by attacker’s attempts to steal data.  
  Capacity / limit exhaustion events for memory, disk, CPU, and other system resources  

