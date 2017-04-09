## Types of evidence  
  
Evidence of Execution  
* AppCompatCache aka Shimcache
* RecentFileCache.bcf
* Amcache
* Prefetch
* UserAssist
* MUICache
File Creation, Modification, and Access  
* MFT
* USNJrnl
Document Creation and Opening  
* LNK
* Jumplists
Explorer interactions  
* Shellbags
* OpenSaveMRU
* LastVisitedMRU
* (Office) Recent Files
* RunMRU
* WordWheelQuery
* TypedPath
* TypedURL
* MountPoints2
Networking  
* SRUM

## Tools to use for evidence
[Tools of the Game under github.com/marcurdy](ToolsOfTheGame.md)  
  
  
## Locations of evidence

### REGISTRIES

1. **NTUSER.dat:**  
   * Location: Win2003-: %SYSTEMROOT%\Document and Settings\%USERNAME%  
               Vista+: %USERPROFILE%
   * **UserAssist:** 
     * Purpose: Track user interaction in Explorer including start->programs but not start->run or by typing the app name
     * Location: NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count 
     * Contains 2+ keys of GUIDs, 64-bit timestamp (last time run) and a occurance count
	 * UEME_RUNPATH indicates an executable file was accessed
	 * UEME_RUNPIDL is a pointer to an ItemIdList structure, i.e. a folder or shortcut
	 * UEME_RUNCPL referring to Control Panel applets being clicked
   * **MUICache:**
     * Purpose: Executables w/o dates based on shell interactions
     * Location:  
       * (XP, 2003) ntuser.dat\Software\Microsoft\Windows\ShellNoRoam\MUICache
       * (Vista+) ntuser.dat\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
   * **Shellbags:** (XP, 2003 only)
     * Purpose: Tracks Explorer viewing preferences
     * Location: XP NTUSER.DAT\Software\Microsoft\Windows\Shell*
       For newer systems, see USRCLASS.DAT
     * Can contain GUID to folder MRU, control panel, MFT reference number, external storage, zipped archives, explorer ftp
   * **OpenSaveMRU:** 
     * Purpose: Tracks files opened or saved within a Windows shell dialog box
     * Location: XP NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU
                 Win7 NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU
   * **LastVisited/MRU:** 
     * Purpose: Tracks executables used by app to open documents in OpenSaveMRU key
     * Each list could have a diff method for identifying order
     * Location: XP NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU  
                 Win7 NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
   * **Recent Files:** 
     * Purpose: tracks files or folders within the "Recent" under the start menu
     * Location: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
   * **Office Recent Files:** 
     * Purpose: Office specific recent files
     * Location: NTUSER.DAT\Software\Microsoft\Office\VERSION
      14.0 = Office 2010, 12.0 = Office 2007, 11.0 = Office 2003, 10.0 = Office XP
   * **RunMRU:** 
     * Purpose: Tracks app run under start->programs choice
     * Location: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
   * **XPSearch:** 
     * Purpose: contains search history on XP
     * Location: NTUSER.DAT\Software\Microsoft\SearchAssistant\ACMru\####
   * **Win7Search (WordWheelQuery):**
     * Purpose: contains search history on Win7
     * Location: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
   * **TypedPath:**
     * Purpose: History of typed paths in searches from Explorer or right of Windows icon
     * Location: ntuser.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
   * **TypedURL:** 
     * Purpose: History of typed URL's
     * Location: NTUSER.DAT\Software\Microsoft\Internet Explorer\TypedURLs
   * **Map Network Drive MRU:**
     * Purpose: Per user history of networking mapping
     * Location: ntuser.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU  
       Location: ntuser.dat\Network\Z  
   * **MountPoints2:**
     * Purpose: Find users that accessed a USB device
     * Location: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
     * Last write time of key is the last time the USB device was attached
   * **Runkey:** 
     * Purpose: Process execution starting at user login
     * Location: Seek external resource for a complete list
     * RunOnce: Deleted after running unless prepended with "!"
   * **TrustRecords:**
     * Purpose: User clicked enable editing in Office. Not indicator of Enable Macros.
     * Location: HKCU\Software\Microsoft\Office\15\Word\Security\Trusted Documents\TrustRecords

2. **USRCLASS.DAT**
   * Location: Win2003- : %USERPROFILE%\Local Settings\Application Data\Microsoft\Windows\
               Vista+   : %USERPROFILE%\AppData\Local\Microsoft\Windows\
   * MUICache : (Vista+) Executables w/o dates based on shell interactions
     * usrclass.dat\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
     * usrclass.dat\Local Settings\MuiCache

* Shellbags: (Vista+)
     * Location: USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell*
   * Autostart: InProcServer (Software, NTUser, USRClass)

2. **SECURITY**
   * Location: %WINDIR%\system32\config\Security
   * Audit policy query
  
3. **SAM**
   * Location: %WINDIR%\system32\config\SAM
   * Local Users and Groups and their security identifiers
   * Users Key: SAM\Domains\Account\Users
  
4. **SYSTEM**
   * Location: %WINDIR%\system32\config\SAM
   * Services
   * AppCompatCache
     * Purpose: Application compatibility database
     * Location: XP            SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatibility
                 Win7,Win2003+ SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
     * Provides: last modify date and file path
     * For Win7 and later, this moved out of registry to Amcache and RecentFileCache.bcf
   * Legacy Registry Keys: First time service executed, DLL/driver path
   * USB: Devices recorded under ControlSet00#\Enum\USBStor/USB
     Mounts of them under MountedDevices and Control\DeviceClasses
   * Interesting Keys
     * Prefetch is disabled/enabled in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\
       Memory Management\PrefetchParameters
     * ClearPagefileAtShutdown
       * Existing Page Files
       * PagingFiles
     * NtfsDisableLastAccessUpdate
     * NtfsDisable8dot3NameCreation
   
5. **SOFTWARE**
   * Location: %WINDIR%\system32\config\SAM
   * List of installed software by way of the Uninstall key
     * Location: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall
   * Vista/Win7 Network History: Tracks networks, last access time, SSID, domain name, gateway MAC
     *  Location: SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\*
   * ProfileList of accounts both local and domain
     * Location: SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
   * Networking Config
   * Persistence
     * Run key for persistence by administrator - boottime
     * Image File Execution Options / StickyKeys  (runs app at other app exec)
     * appinit_DLLs (inject dll's into path)
     * Shell Extensions
     * Browser Helper Object (BHO)
     * Scheduled Tasks (can exec at login) schtasks & at
     * Autostart: InProcServer (Software, NTUser, USRClass) 
   * SysInternals keys eg. Software\SysInternals\Strings = EulaAccepted
     * Time relates to when app was first run
   * Disable UserAssist: 
     * Location: XP HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
                 Vista HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs
   
7. **Amcache.hve:** 
   * Purpose: Win8 replacement of Application compatibility database
   * (Called Appcompatcache Win7 and earlier. Called RecentFileCache.bcf in Win7)
   * Location: %WINDIR%\AppCompat\Programs\Amcache.hve
   * Provides: volume guid, first run, file path, file size, SHA1
   * Program subkey contains MSI installed files

### NON-REGISTRY ARTIFACTS

8. **Jumplists in Win7+**
   * Path: %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
   * Provides: First time of execution, last time of execution

9. **RecentFileCache.bcf:**
   * Purpose: Windows application compatibility database for Win7
   * Location: %WINDIR%\AppCompat\Programs\

10. **Prefetch:** 
    * Purpose: Increases performance by pre-loading code pages of run apps
    * Location: Win7/XP %WINDIR%\Prefetch
    * Disabled on server builds 
    * Executable, run count, size of pf, files/dirs referenced, volume
    * pf creation is first execution
    * last modify time is last time it was executed
    * Examine files/dir mapped by this and for files in close time prox
  
11. **MFT:**
    * Location: %SYSTEMROOT%\$MFT
    * Full filename
    * Parent directory
    * File size, Creation Date, Mod Date, MFT Change Date, Access Date
    * Change times cannot be edited with a Windows API
    * $File_name timestamps are based on movement in b-tree
    * $Standard_Information timestamps are for MACE. Easily timestomped
    * $I30 timestamps are FN not SI timestamps

12. **USNJrnl**
    * Records file/folder changes
    * Time of Change, reason, file/dir name, MFT record number, 
  
13. **Shortcut LNK files:** 
    * Location: XP %SYSTEMROOT%\Documents and Settings\%USERPROFILE%\Recent\
                Win7 %USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\
                Win7 %USERPROFILE%\AppData\Roaming\Microsoft\Office\Recent\
    * Automatically created links. Not for manual shortcuts
    * First and last time of opening (creation and last modified date)
    * LNKTarget File (Internal LNK File Information) Data:
      * Modified, Access, and Creation times of the target file
      * Volume Information (Name, Type, Serial Number), Name of System
      * Network Share information, Original Location
    
14. **SRUM (System Resource Utilization Manager database)**
    * Location: %WINDIR%\sru
    * Network and length of connection, bytes written to HDD, applications executed with SID and runtimes

15. **IExplore index.dat:** IE activity.  Local and remote file activity via network shares
    * Does not limit to actiity run in Internet Explorer 
    * Location: XP %userprofile%\Local Settings\History\History.IE5
                Win7 %APPDATA%\Local\Microsoft\Windows\History\History.IE5
                Win7 %APPDATA%\AppData\Local\Microsoft\Windows\History\Low\History.IE5

16. **Applets:** eg. regedit, wordpad, ms paint
    * regedit nas lastkey value
    * wordpad has recent file list

### References:  
* https://tzworks.net/prototypes/cafae/cafae.users.guide.pdf
* https://digital-forensics.sans.org/community/cheat-sheets
* https://www.elsevier.com/books/windows-registry-forensics/carvey/978-0-12-803291-6
* I also thank the dozens of others where I found one-off details  
