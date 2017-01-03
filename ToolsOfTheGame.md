# dfir-toolset
I'm collecting, sorting, and making order out of the available tools.  I'm housing my experience with opensource tools with an emphasis on Linux as the DF host OS.  Much of this comes from Remnux and SIFT.  A few come from Kali.  Others are pulled straight from Github.  I am working to eliminate the noise caused by orphaned, redundant, or superceded all-in-one software.  

**Links to other lists of awesome tools**
* IR https://github.com/meirwah/awesome-incident-response
* Malware Analysis https://github.com/rshipp/awesome-malware-analysis
* Threat Intel https://github.com/hslatman/awesome-threat-intelligence
* Sec Talks https://github.com/PaulSec/awesome-sec-talks
* D3Pak list https://www.linkedin.com/pulse/computer-forensic-deepak-kumar-d3pak-

**Distributions for Security tools**
* SIFT and/or Remnux on top of Ubuntu 14.04
* DEFT (Windows)   
* Security Onion (Network Security Monitor)
    
**Mounting dd or vm snapshot disk images**  
* evmount, my very own github provided VMDK, EWF, raw disk, and LVS friendly mount tool!
* For "read-write" mounts use xmount (rw made available with cache)

**Volume Shadow Copy browsing**  
* libvshadow FUSE mounting (vshadowinfo, vshadowmount)
  
**Checking file signed signatures**  
* AnalyzePESig (Process Manager with benefits)
* Process Manager (SysInternals)
* chktrust (Runs Mono for Linux)

**Browser Artifact tools**
* If Ediscovery, see Plaso, FTK, Xways, Encase, and Autopsy
    
**Scan for IOC, hashing, and hash lookups**  
* Parse IOC's from reports: IOCextractor, ioc-parser
* Define signatures: YaraGenerator, Autorule, Rule Editor, IOC writer, ioc_editor, pyioce
* Offline-Scan: yara (IOC), clamAV, fenrir
* Metadata: trID (determine filetype), exifTool, missidentify (find PE in files not named exe)
* Gen Hashes: ssdeep(fuzzy hashes) w pydeep for bindings, md5deep (recursive md5 checks) / hashdeep (audit across multiple sets), hash_id (guess hash algorithm used), 
* Hashes Query: nsrllookup (Whitelist of non-malicious hashes) requiring nsrlsvr, virustotal-search, vtTool.py, Automater (search by URL, IP, Hash), fileintel
  
**File Forensics**  
* Sleuthkit suite
* scalpel (image scraping)
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
  
***Windows Event Log analysis***  
**Windows only tools**
* Event Log Explorer
* Log Parser Lizard - gui for MS Logparser
* Mandiant Highlighter
**Linux friendly**
* python-evtx (WilliB) Can recover from corrupted evtx's  
* libevtx (Metz)  
* evtwalk/evtx_view (tzworks-commercial)  

***Registry Viewing and Parsing***
**Exploring the registry**
* Registry Explorer (Windows)
* Registry Viewer (AccessData, Windows)
* Registry Decoder (Digitial Forensic Solutions)
* MiTeC Windows Registry Recovery (Windows)
* Yaru (tzworks-commercial)
* Regshot (Windows)
  pstpassword  

**All-in-one registry parser**
* cafae (tzworks-commercial)
* RECmd (Windows)
* RegRipper (WINE friendly)

**Prefetch analysis**  
* PECmd (Windows)
* pf (tzworks-commercial)  
* MiTec Windows File Analyzer (also view lnk, shortcut, index.dat, recyclebin)

**Amcache parsing**  
* amcache.py
* AmcacheParser (Windows)

**LNK parsing**  
* LECmd (Windows)
* lp (tzworks-commercial)  
* MiTec Windows File Analyzer
  
**Jumplist parsing**  
* JLECmd (Windows)
* jmp (tzworks-commercial)  

**Shellbags parsing**
* sbags (tzworks-commercial) 
* Shellbags Explorer (Windows)

**AppCompatCache / Shimcache**
* AppCompatCacheParser (Zimmerman)  
* ShimCacheParser (Mandian)
* wacu (tzworks-commercial) use -all_controlsets option  
* shims (tzworks-commercial) 

**NTFS MFT parsing**
* jp (Journal Parser, tzworks-commercial)
* ntfsdir (NTFS Directory Enum, tzworks-commercial))  
* ntfswalk (NTFS Metadata Extractor, tzworks-commercial))  
* INDXParse.py
* AnalyzeMFT
* wisp (INDX Slack Parser, tzworks-commercial)   

**Scheduled Task (AT) job parser
* jobparser.py

**TZWorks suite: Others**  
* Artifacts
  id (index.dat Parser)  
* NTFS Analysis  
  elmo (Event Log MessageTables Offline)   
* Other
  DNS Query Utility (dqu)
  Packet Capture ICMP Carver (pic)
  Network Xfer Client/Server (nx)
  Volume Shadow Snapshot Enum (vssenum) 
  CSV Data eXchange (csvdx) 
  Windows Symbol Fetch Utility (sf)
  
**Extract and Decode Artifacts**  
* Deobfuscate: unXOR, XORStrings, ex_pe_xor, XORSearch, brxor.py, xortool, NoMoreXOR, XORBruteForcer, Balbuzard
* Extract strings: strdeobj, pestr, strings.exe (wine)

**Examine Document Files**  
* PDF: pdfid, pdf-parser (Didier Stevens), AnalyzePDF, Pdfobjflow, peepdf, Origami, PDF X-RAY, 
* Continued: PDFtk, swf_mastah, qpdf, pdfresurrect
* VBE decoding: decode-vbe.py (Didier)
* MS Office XML: officeparser.py, mastiff (Win Py modules require Visual Studio)
* MS Office OLE: oletools (Didier Stevens), pyOLEScanner.py, libolecf, oledump, olefile, offviz(Win)
* Shellcode: sctest, unicode2hex-escaped, unicode2raw, dism-this, shellcode2exe, base64dump.py
* Flash: xxxswf, SWF Tools, RABCDAsm, extract_swf, Flare(decompiler of Flash), flasm(disassembles Flash)
* Java: Java Cache IDX Parser, JD-GUI Java Decompiler, JAD Java Decompiler, Javassist, CFR
* JavaScript: Extract/unpack: Extractscripts, extractjs.rb (Oragami), jsunpack-n (pdf.py)
* Debug/manip: Rhino Debugger, Firebug, Didier's SpiderMonkey, V8, js Beautifier, JSDetox, 
    
**Mail**  
* OST Viewer, PST Viewer (Nucleus Technologies)
* readpst
* MSGConvert
* emldump
* Digital Forensic Framework by Arxsys (Test free version)
* mpack/munpack for mime

**Binary/Hex Editors**  
* Binary: wxHexEditor, VBinDiff
* Hex: bless, exhexeditor

**Examine Memory Snapshots**  
* Volatility frameworks/wrappers  
  * VolUtility - Complete front/backend for using Volatility past just module exec
  * Evolve - Creates sqllite db output and web frontend  
  * volshot - antiquated.  Hand edit to add modules  
  * Bulk_extractor module for grabbing types of data with beviewer for viz
  * Volatility module add-ons of notability (within SIFT add-on)
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
* Find anomalies: signsrch, pescanner, exescan, pev suite, peframe, pedump, disitool (alter digsig), pe_view/pescan (tzworks)
* Trace: strace, ltrace
* Static Analysis: Radare, Pyew, Bokken(front-end to radare/pyew), m2elf
* Disassemblers: Vivisect, Udis86, objdump, jad (java decom), recstudio, mastiff, captone, EmilPRO, 
*   Continued: distorm, Decompyle++ (python disassembler)
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
* dislocker (bitlocker decrypting for Linux)

**Super Timelining**  
* log2timeline w/ plaso
* CDQR
* Timesketch
  
**Rootkit detection**  
* GMER (Windows)  
* Rootkit revealer (Windows)  
* Rootkit remover (mcafee win)  
* chkrootkit  
  
** USB analysis
* usbdeview - see s/n of drives inserted  
* usp (USB Storage Parser, tzworks-commercial)
* uvcview (pull sn off usb), usbdeviceforensics  

**Windows client evidence collection
* fastIR (collect artifacts)  
* dumpzilla
* DumpAutoComplete (firefox autocomplete dump)  
* Mandiant web historian  
* IEPassView on live system for protected to recover protected browser artifacts  
* Magnet's IEF $$$ (Scraping for chat/webmail logs)  
  
**Windows Miscellaneous  
* Forensic toolkit (view files without touching metadata by Mcafee)  
* shoWin (reveal passwords by Mcafee)  
* Vision (maps net ports to apps by Mcafee)  

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
