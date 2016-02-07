#### 1. Mount/Unmount the Encase images  
  
    #Point DATAFILES to your images using wildcards
    DATAFILES="/home/sansforensics/Downloads/blackshirt/Computer1.E??"
    if [ -z "$1" ]; then
        echo 'Usage: mount_ewf.sh <-m|-u>'
        echo 'Usage: -m=mount -u=unmount'
        exit 0
    fi
    if [ "$1" == '-u' ]; then
        mount | grep 'mapper/loop' | awk '{ print $3 }' | while read LO; do
            umount $LO
        done
        kpartx -d /media/xmnt/*.dd
        umount /media/xmnt
        pkill xmount
        rm -f /tmp/cache-xmount
        rmdir /media/xmnt 2>/dev/null
    fi
    if [ "$1" == '-m' ]; then
        mkdir -p /media/xmnt 2>/dev/null
        #xmount creates a cache to add pseudo RW to many image types
        xmount --in ewf --cache /tmp/cache-xmount $DATAFILES /media/xmnt
        #kpartx auto-creates loopback devices based intelligently on an image (requires rw)
        kpartx -a -v /media/xmnt/*.dd
        ls -1 /dev/mapper/loop* | while read LO; do
            mountname=`basename $LO`
            mkdir /media/$mountname 2>/dev/null
            #Exposes the MFT, etc, but as per https://github.com/log2timeline/plaso/wiki/Tips-and-Tricks, plaso doesn’t handle MFTs directly. See steps 7-10below
            mount -o ro,show_sys_files,streams_interface=windows $LO /media/$mountname
        done
        mount | grep loop
    fi
