### Mounting an image and running a timeline against an offline FS  

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
  
#### Timeline the mounted systems  
5. log2timeline.py -hashsers md5 -z CST6CDT /data/HOSTNAME/HOSTNAME_1.pb /MOUNTPOINT2  
6. log2timeline.py -hashsers md5 -z CST6CDT /data/HOSTNAME/HOSTNAME_2.pb /MOUNTPOINT3  
7. analyzeMFT.py --bodyfull -b /data/HOSTNAME /HOSTNAME1.bodyfile -f /MOUNTPOINT2/\$MFT  
8. analyzeMFT.py --bodyfull -b /data/HOSTNAME /HOSTNAME2.bodyfile -f /MOUNTPOINT3/\$MFT  
9. log2timline.py  /data/HOSTNAME/HOSTNAME_1.pb /data/HOSTNAME /HOSTNAME1.bodyfile  
10. log2timline.py  /data/HOSTNAME/HOSTNAME_2.pb /data/HOSTNAME /HOSTNAME2.bodyfile  
   
#### Generate CSVs
11. psort -analysis tagging -o l2tcsv -w /data/HOSTNAME/HOSTNAME_1.csv /data/HOSTNAME/HOSTNAME_1.pb
12. psort -analysis tagging --tagging-file /usr/share/plaso/tag_windows.txt -o l2tcsv -w /data/HOSTNAME/HOSTNAME_2.csv /data/HOSTNAME/HOSTNAME_2.pb
 * extra argument needed because it is not OS root drive  
