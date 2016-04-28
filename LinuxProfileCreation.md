***First check the volatility plugin github for existing profiles.  If yours is not there, roll your own.

**Download the distro whose release, architecture, and kernel version match that of the target server
* HPE has all distros at blofly.us.rdlabs.hpecorp.net

**Install the OS as a VM

**Install libdwarf and libdwarf-tools
*You might need to find the specific binaries off a site like rpm.pbone.net
*ex. http://rpm.pbone.net/index.php3/stat/4/idpl/26992674/dir/redhat_el_6/ 

**On any system, we need linux source code to build the dwarf module.
* git clone https://github.com/volatilityfoundation/volatility.git
* cd volatility/tools/
* copy the linux tree to the above VM
* Within linux/, type make to produce module.dwarf
* cp /boot/System.map-* .
* zip <Distro><version>-profile.zip module.dwarf System.map*

**Copy the zip to the Global lab server under \Software\LimeLinuxMemoryDump\

**This is your volatility profile
