### Mounting an image and running a timeline against an offline FS  
  
#### Setup mounts  
##### xmount creates a cache to add pseudo RW to many image types  
##### kpartx auto-creates loopback devices based intelligently on an image (requires rw)  
1. xmount --in ewf FILENAME.E?? --cache /data/HOSTNAME/cache /MOUNTPOINT
 * the ?? is a regex that will allow bulk processing of all the images  
2. kpartx -a -v /MOUNTPOINT/HOSTNAME.dd
 * this creates the /dev/mapper/loop0p1 etc for the next step
3. mount -o ro,show_sys_files,streams_interface=windows /dev/mapper/loop0p2 /MOUNTPOINT2
 * this should expose the MFT etc but as per https://github.com/log2timeline/plaso/wiki/Tips-and-Tricks, plaso doesn’t handle MFTs directly see steps 7-10  below
4. #mount /dev/mapper/loop0p3 /MOUNTPOINT3 -o ro,show_sys_files,streams_interface=windows
   
#### Timeline the mounted systems  
5. log2timeline.py -hashsers md5 -z CST6CDT /data/sternwindow/HOSTNAME/HOSTNAME_1.pb /MOUNTPOINT2  
6. log2timeline.py -hashsers md5 -z CST6CDT /data/sternwindow/HOSTNAME/HOSTNAME_2.pb /MOUNTPOINT3  
7. analyzeMFT.py --bodyfull -b /data/sternwindow/HOSTNAME /HOSTNAME1.bodyfile -f /MOUNTPOINT2/\$MFT  
8. analyzeMFT.py --bodyfull -b /data/sternwindow/HOSTNAME /HOSTNAME2.bodyfile -f /MOUNTPOINT3/\$MFT  
9. log2timline.py  /data/sternwindow/HOSTNAME/HOSTNAME_1.pb /data/sternwindow/HOSTNAME /HOSTNAME1.bodyfile  
10. log2timline.py  /data/sternwindow/HOSTNAME/HOSTNAME_2.pb /data/sternwindow/HOSTNAME /HOSTNAME2.bodyfile  
   
#### Generate CSVs
11. psort -analysis tagging -o l2tcsv -w /data/sternwindow/HOSTNAME/HOSTNAME_1.csv /data/sternwindow/HOSTNAME/HOSTNAME_1.pb
12. psort -analysis tagging --tagging-file /usr/share/plaso/tag_windows.txt -o l2tcsv -w /data/sternwindow/HOSTNAME/HOSTNAME_2.csv /data/sternwindow/HOSTNAME/HOSTNAME_2.pb
 * extra argument needed because it is not OS root drive  
  
### Cleanup  
13. umount /MOUNTPOINT2  
14. umount /MOUNTPOINT3  
15. umount /MOUNTPOINT   
16. kpartx -d /MOUNTPOINT/HOSTNAME.dd  
