***First check the volatility\profiles github for existing profiles.  If yours is not there, roll your own.

**Download the distro whose release, architecture, and kernel version match that of the target server

**Install the OS as a VM

**Install libdwarf and libdwarf-tools
*You might need to find the specific binaries off a site like rpm.pbone.net
*ex. http://rpm.pbone.net/index.php3/stat/4/idpl/26992674/dir/redhat_el_6/ 

**Offline, fetch the Volatility source code to build the dwarf module.
* git clone https://github.com/volatilityfoundation/volatility.git
* cd volatility/tools/
* copy the linux tree to the above VM
**Back in the VM within the copied linux/, type make to produce module.dwarf
* cp /boot/System.map-* .
* zip <Distro><version>-profile.zip module.dwarf System.map*

**This is your volatility profile. Put it in the volatility/plugins/overlaps/linux
