VOLATILE DATA COLLECTION STEPS  
• System date and time
• On the compromised machine, run a trusted command shell with statically compiled binaries
• Run script to start a log of your keystrokes. Terminate at completion by typing exit.  
• Document the date and time of the computer and compare it with a reliable time source.  
• Acquire contents of physical memory.  
• Gather hostname, IP address, and operating system details.  
• Gather system status and environment details.  
• Identify users logged onto the system.  
  wtmpx and archived versions using last
• Inspect network connections and open ports and associated activity.  
• Examine running processes, tree format, and pmap or lsof  
• Correlate open ports to associated processes and programs.  
• Determine what files and sockets are being accessed.  
• Examine loaded modules and drivers.  
• Examine connected host names.  
• Examine command-line history.  
• Identify mounted shares.  
• Check for unauthorized accounts, groups, shares, and other system resources and configurations.  
  rhosts, fstab, export, /etc/hosts.*, /etc/X*hosts and ~home/.Xauthority, ~home/.ssh/authorized_keys
• Determine scheduled tasks.  /var/spool and /etc/crontabs.*
• Determine audit policy configuration.  
• printenv to print environment variables
• /proc/version for compiler version
• /proc/<pid>/fd and maps
• sa command if auditd is running
• Look if eth is in permiscuous mode - netstat -i  - flag = P
• Harvest process details, loaded modules, network connections and compare against memory dump forensics
• File listing of each partition during the live response using The SleuthKit
  (e.g., fls /dev/hda1 –lr -m /

Optional during live response for data gathering
• gcore <pid> to dump individual process for use in gdb
• memfetch on github to dump processes for strings searching

Post Collection Forensics
• Look for common indicators of malicious code including memory injection and hooking.
• Recover the executable code and process memory from capture for further analysis
• Perform keyword searches for known details relating to a malware incident
• Extract contextual details such as URIs, system logs, and configuration values
• Perform temporal and relational analysis of information including a timeline

Cold disk techniques
• Search for Known Malware
  NSRL, hashes, packaging system self-verifies (Rpm -Va)
  rkhunter, chkrootkit
  AV, keywords
• Survey Installed Programs
• Inspect Executables
• Review Services, Modules, and Auto-start Locations
• Review Scheduled Jobs
• Examine Logs (system logs, AntiVirus logs, Web browser history, etc.)
• Review User Accounts
• Examine File System
  Histogram of activity spikes
  Search for archives to indicate possible exfiltration
  Search for files round the time of know breach
  Look for non-block or char devices in /dev
  Look for suid files find /mnt/evidence -user root -perm -04000 –print
  Inodes are assigned sequentially. Look at neighbor inodes to suspicious files.  Look for outliers in OS binary directories
  For non-root suspicious files, look for other files with the same ownership
  The journal on EXT3 and EXT4 contains references to file system records that can be examined using the jls and jcat utilities in TSK
• Examine Configuration Files
• Perform keyword searches for any specific, known details relating to a malware incident. Useful keywords may come from other forms of analysis, including memory forensics and analysis of the malware itself.
• Harvest available metadata including file system date-time stamps, modification times of configuration files, e-mails, entries in Web browser history, system logs, and other logs such as those created by AntiVirus, crash dump monitoring, and patch management programs. Use this information to determine when the malware incident occurred and what else was done to the system around that time, ultimately generating a time line of potentially malicious events.
• Look for common indicators of anti-forensics including file system date-time stamp alteration, log manipulation, and log deletion.
• Look for links to other systems that may be involved.
• Look for data that should not be on the system such as directories full of illegal materials and software or data stolen from other organizations.
• Examine Application Traces
  ssh: ~/.ssh/authorized_keys and known_keys
  gnome: recently_userd.xbel or similar source
  vim: ~/.viminfo
  All ~home/.config's
• Keyword Searches
  Malware characteristics, command-line commands, IP's, URL's, Passwords, hostnames, file extensions, date timestamps, 

File Identification and Profiling
• Compilation details
  Static or Dynamically linked
  Debug information in executables may contain names and addresses of all functions; the names, data types, and addresses of global and local variables; and the line numbers in the source code that correspond to each binary instruction
  nm to identify debug and symbolic information in ELF that can expose source code filenames. LC symbol is local. UC is global.
  eu-nm includes the designation and listing of the symbol name, value, class, type, size, line, and respective ELF section
  When examining nm output, be mindful of references to:
  -ELF sections
  -Function calls
  -Attack commands
  -Compiler type and version used to create the program
  exiftools can view ELF metadata
• FS timestamps
  stat shows the MACB dates.  istat against the inode gives more details. debugfs gives birth time
  fsstat -Displays details about the file system
  # fsstat imagefile.dd
  Data Layer Tools (Block or Cluster)
  blkcat -Displays the contents of a disk block
  # blkcat imagefile.dd block_num
  blkls -Lists contents of deleted disk blocks
  # blkls imagefile.dd > imagefile.blkls
  blkcalc -Maps between dd images and blkls results
  # blkcalc imagefile.dd -u blkls_num
  blkstat -Display allocation status of block
  # blkstat imagefile.dd cluster_number
  MetaData Layer Tools (Inode, MFT, or Directry Entry)
  ils -Displays inode details
  # ils imagefile.dd
  istat -Displays information about a specific inode
  # istat imagefile.dd inode_num
  icat -Displays contents of blocks allocated to an inode
  # icat imagefile.dd inode_num
  ifind -Determine which inode contains a specific block
  # ifind imagefile.dd –d block_num
  Filename Layer Tools
  fls -Displays deleted file entries in a directory inode
  # fls -rpd imagefile.dd
  ffind -Find the filename that using the inode
  # ffind imagefile.dd inode_num
• FS extensions vs content with "file" or "TriD" where the latter gives % of confidence against many types
• bytehist makes a histogram out of the ELF components
• Packed binary detection
  strings returns nothing
  file shows corrupt section header
  staticly compiled
  
Actiity tracker for Linux executables is InstallWatch7
Look for new timestamps
GLSOF is a gui monitor incorporating FileMonitor and Queries utilizing lsof.
EtherApe for graphic visualization
Capture impression evidence during ELF exec with SystemTap, inotify, FAM, Gamin
Linux firewalls for per-application access to network: Leopard Flower, Program Guard pgrd
