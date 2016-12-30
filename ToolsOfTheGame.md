# dfir-toolset
I'm collecting, sorting, and making order out of the available tools.  I'm housing my experience with opensource tools with an emphasis on Linux as the DF host OS.  Much of this comes from Remnux and SIFT.  A few come from Kali.  Others are pulled straight from Github.  I am working to eliminate the noise caused by orphaned, redundant, or superceded all-in-one software.  

**Links to other lists of awesome tools**
* IR https://github.com/meirwah/awesome-incident-response
* Malware Analysis https://github.com/rshipp/awesome-malware-analysis
* Threat Intel https://github.com/hslatman/awesome-threat-intelligence
* Sec Talks https://github.com/PaulSec/awesome-sec-talks

**Distributions for Security tools**
* SIFT + Remnux
* DEFT (Windows)   
* Security Onion
    
**Mounting dd or vm snapshot disk images**  
* My very own github provided VMDK mount tool!
* For "read-write" mounts use xmount (rw w/ cache for EWF,VMDK,etc)
* kpartx for automatic mounting of found filesystems (not a swiss army knife)

**Volume Shadow Copy browsing**  
* libvshadow FUSE mounting (vshadowinfo, vshadowmount)
  
**Checking file signed signatures**  
* Authenticode Tools (Didier Stevens)
* Process Manager (Windows SysInternals)
* chktrust (Runs Mono for Linux)

**Browser Artifact tools**
* Not listing per artifact type tools.  See Plaso, FTK, Xways, Encase, and Autopsy
    
**Scan for IOC, hashing, and hash lookups**  
* Parse IOC's from reports: IOCextractor, ioc-parser
* Define signatures: YaraGenerator, Autorule, Rule Editor, IOC writer, ioc_editor, pyioce
* Offline-Scan: yara (IOC), clamAV, fenrir
* Metadata: trID (determine filetype), exifTool, missidentify (find PE in files not named exe)
* Gen Hashes: ssdeep(fuzzy hashes) w pydeep for bindings, md5deep (recursive md5 checks) / hashdeep (audit across multiple sets), hash_id (guess hash algorithm used), 
* Hashes Query: nsrllookup (Whitelist of non-malicious hashes) requiring nsrlsvr, virustotal-search, vtTool.py, Automater (search by URL, IP, Hash), fileintel
  
**File Forensics**  
* Autopsy the Sleuthkit
* scalpel (not foremost anymore)
* safecopy (file restore from damaged sources)
* analyze mft (parse the mft from an ntfs FS)
* hachoir (Read windows metadata)
* Rifiuti (recycle bin analysis)
* testdisk (restore lost partitions), kpartx
* extundelete (ext3/4 file rest), recoverjpeg, vinetto (thumbs.db examiner)
  
**Handle Network Interactions**  
* Sniffing: ngrep, tcpdump, tcpick(passive sniffer), tcptrack, driftnet, tshark (terminal wshark),
dsniff(captures user data over common protos), aircrack-ng (WEP and WPA-PSK keys cracking), 
yaraPcap.py (http streams)
* Analyze/Exec pcap: ssldump(decode ssl/tls records), tcpxtract, tcpreplay (can't estab session), tcptrace (stats on pcaps), tcpflow (deconstruct), tcpcopy (resend data), chaosreader.pl (dump http conversations), CapTipper (emulate web svr of what's in pcap), Xplico (extract data per protocol), networkminer, scapy (BYO packets), editcap (convert formats)
* Services: FakeDNS, Nginx, fakeMail, Honeyd, INetSim
* Reporting: etherape(graphical network monitor), Wireshark
* MITM: Burp Proxy (manipulate http between web and client), ettercap (content filtering on fly), sslsniff (MITM attacker), mitmproxy, sslcaudit (test ssl), sslstrip, sslsplit
* Honeypots: Thug (docker based honeypot), Dionaea (honeypot), Kippo (SSH), Modern Honeypot Network
* Miscellaneous network: prettyping, Netcat, stunnel, p0f(passive remote fingerprinting), netwox(swiss-army knife of routines), lft(smart traceroute), passivedns, tcpstat(stats on NIC), 
  
**Windows Event Logger analysis**  
* Event Log Explorer - eventlogxp.com
* Log Parser Lizard - gui for logparser
* Mandiant Highlighter

**Registry Manipulation**  
* Registry Explorer (Zimmerman, Windows)
* Registry Decoder
* regripper (wine friendly)
* MiTeC Windows Registry Recovery (Windows)

**Linux Event Log analysis**  
* python-evtx (WilliB) Can recover from corrupted evtx's
* libevtx (Metz)
* evtwalk: See TZWorks section
  
**Extract and Decode Artifacts**  
* Deobfuscate: unXOR, XORStrings, ex_pe_xor, XORSearch, brxor.py, xortool, NoMoreXOR, XORBruteForcer, Balbuzard
* Extract strings: strdeobj, pestr, strings.exe (wine)

**Examine Document Files**  
* PDF: AnalyzePDF, Pdfobjflow, pdfid, pdf-parser, peepdf, Origami, PDF X-RAY, PDFtk, swf_mastah, qpdf, pdfresurrect
* MS Office XML: officeparser.py, mastiff (Win Py modules require Visual Studio)
* MS Office OLE: pyOLEScanner.py, oletools, libolecf, oledump, olefile, offviz(Win)
* Shellcode: sctest, unicode2hex-escaped, unicode2raw, dism-this, shellcode2exe, base64dump.py
* Flash: xxxswf, SWF Tools, RABCDAsm, extract_swf, Flare(decompiler of Flash), flasm(disassembles Flash)
* Java: Java Cache IDX Parser, JD-GUI Java Decompiler, JAD Java Decompiler, Javassist, CFR
* JavaScript: Extract/unpack: Extractscripts, extractjs.rb (Oragami), jsunpack-n (pdf.py)
              Debug/manip: Rhino Debugger, Firebug, Didier's SpiderMonkey, V8, js Beautifier, JSDetox, 
    
**Mail**  
* readpst
* MSGConvert
* emldump
* Digital Forensic Framework by Arxsys (Testing free version)
* mpack/munpack for mime

**Binary/Hex Editors**  
* Binary: wxHexEditor, VBinDiff
* Hex: bless, exhexeditor

**Examine Memory Snapshots**  
* Volatility frameworks/wrappers  
  * Evolve - Creates sqllite db output and web frontend  
  * vshot - becoming antiquated.  Hand edit to add modules  
  * Mantaray - becoming antiquated  
  * Bulk_extractor modules for grabbing types of data  with beviewer for viz
  * Volatility module add-ons of notability  
    * prefetch, shimcachemem, usnparser, idxparser
    * autoruns, uninstallinfo, pstotal
    * chromehistory, firefoxhistory
    * hollowfind, psinfo
    * apihooksdeep, malfinddeep, malprocfind, malsysproc
    * mimikatz, openvpn rsakey, ssh_agent_key
    * baseline, ssdeepscan  
* Rekall (Volatility fork relying on API's and not scanning to find evidence)  
* findaes, AESKeyFinder, RSAKeyFinder, VolDiff  
* pdgmail (gmail from mem)  

**Investigate Malware**  
* System: Unhide(detect hidden processes), sysdig (strace + tcpdump + htop + iftop + lsof)
* Find anomalies: signsrch, pescanner, exescan, pev suite, peframe, pedump, disitool (alter digsig)
* Trace: strace, ltrace
* Static Analysis: Radare, Pyew, Bokken(front-end to radare/pyew), m2elf
* Disassemblers: Vivisect, Udis86, objdump, jad (java decom), recstudio, mastiff, captone, EmilPRO, distorm, Decompyle++ (python disassembler)
* Debug: Evan s Debugger (EDB), GNU Project Debugger (GDB), pyelftools (ELF parsing), elfutils: Object Viewer, lida
* Packers: UPX, Bytehist, Density Scout, PackerID, Packer Attacker, Burneye (vs burncrack, burninhell, burndump)
* Investigate: RATDecoders, readpe.py, PyInstaller Extractor, DC3-MWCP
* Maltrieve (DL Malware samples), Viper (managing and exploring malware samples), 
* Behavioral analysis: Procdot for visual report, ThreatExpert (online), Cuckoo (offline)

**Password cracking**  
* hydra (brute force pw cracker)  
* samdump2 (dumps windows password hashes)  
* patator  

**Visual Reporting**  
* afterglow (graphs complex datasets)
* mantego
* Elastic Stack

**Memory Capture**  
* dumpit, PMem, fdpro, Mandiant Memoryze to dump on Windows
* pmemsave to dump qemu VM
* Snapshot to take dump of ESX VM
* LiME to extract on Linux
* Linux Memory Grabber - Hal Pomeranz
* PMDump - dump memory of a process

**Disk Capture**  
* ftk imager
* dcfldd (enhanced dd)
* gddrescue/ddrescueview, ddrutility (complements ddrescue)
* rdd

**Super Timelining**  
* log2timeline w/ plaso
* CDQR
* Timesketch
  
**Rootkit detection**  
* GMER (Windows)  
* Rootkit revealer (Windows)  
* Rootkit remover (mcafee win)  
* chkrootkit  
  
**Amcache parsing**  
* amcache.py
* AmcacheParser

**Prefetch analysis**  
* PECmd
  
**LNK parsing**  
* LECmd  
  
**Jumplist parsing**  
* JLECmd  
  
**TZWorks suite**  
* Artifacts
  shims (shim db parser)  
  pf (Prefetch Parser)  
  id (index.dat Parser)  
  lp (LNK Parser)  
  usp (USB Storage Parser)  
  jmp (JumpList Parser)  
* Registry based artifacts
  cafae (query registry)  
  sbags (shell bags parser)  
  yaru (Yet Another Registry Utility)  
  evtx_view (Event log viewer)  
  evtwalk (event log parser)  
  wacu (AppCompatCache)  
* NTFS Analysis  
  elmo (Event Log MessageTables Offline)  
  jp (Journal Parser)  
  ntfsdir (NTFS Directory Enum)  
  ntfswalk (NTFS Metadata Extractor)  
  wisp (INDX Slack Parser)  
* Portable Executable Utilities  
  pe_view (Portable Executable Viewer)  
  pescan (Portable Executable Scanner)  

Network Support Utilities
DNS Query Utility (dqu)
Packet Capture ICMP Carver (pic)
Network Xfer Client/Server (nx)
Portable Executable Utilities
Portable Executable Viewer (pe_view)
Portable Executable Scanner (pescan)
Miscellaneous Tools
Volume Shadow Snapshot Enum (vssenum) 
CSV Data eXchange (csvdx) 
Windows Symbol Fetch Utility (sf)

**Scheduled Task (AT) job parser
* jobparser.py

** Windows Internals Suite**  

Tool | Image Name | Origin 
---- | ---------- | ------  
Startup Programs Viewer | AUTORUNS | Sysinternals
Access Check            | ACCESSCHK | Sysinternals
Dependency Walker       | DEPENDS | www.dependencywalker.com
Global Flags            | GFLAGS | Debugging tools
Handle Viewer           | HANDLE | Sysinternals
Object Viewer           | WINOBJ | Sysinternals
Performance Monitor     | PERFMON.MSC | Windows built-in tool
Pool Monitor            | POOLMON | Windows Driver Kit
Process Explorer        | PROCEXP | Sysinternals
Process Monitor         | PROCMON | Sysinternals
Task (Process) List     | TLIST | Debugging tools
Task Manager            | TASKMGR | Windows built-in tool
  
**Windows client evidence collection
  fastIR (collect artifacts)  
  usbdeview - see s/n of drives inserted  
  uvcview (pull sn off usb), usbdeviceforensics  
  dumpzilla
  DumpAutoComplete (firefox autocomplete dump)  
  Mandiant web historian  
  IEPassView on live system for protected to recover protected browser artifacts  
  Magnet's IEF $$$ (Scraping for chat/webmail logs)  
  
**Windows Miscellaneous  
  Forensic toolkit (view files without touching metadata, Mcafee)  
  shoWin (reveal passwords, Mcafee)  
  Vision (maps net ports to apps, Mcafee)  
  AccessData's registry viewer  
  MiTec Windows File Analyzer (view lnk metadata)  
  pstpassword  

**Sweet Python API Modules Found along the way  
requesocks (http calls for humans)  
fuzzywuzzy (fuzzy string comparison)  
pypdns (passive dns)  
pypssl (passive ssl)  

**Backend tools to use for string search**
* wce.exe (pw retrieval)
* mimikatz.exe (windows exploiter. pull hashes, forge kerberos tickets)
* depends.exe (walk DLL path)
* icacls.exe (check for perm to write to dir of system process)
