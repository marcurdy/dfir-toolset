#### Timeline a mounted Windows partition  
  
DATADIR=/data  
HOSTNAME=loop0p2  
MOUNTPOINT=/media/loop0p2 
  
1. log2timeline.py --status_view window --hashers MD5 -z CST6CDT ${DATADIR}/${HOSTNAME}/${HOSTNAME}_1.pb ${MOUNTPOINT}  
2. analyzeMFT.py --bodyfull -b ${DATADIR}/${HOSTNAME} \/${HOSTNAME}.bodyfile -f ${MOUNTPOINT}/\$MFT  
3. log2timeline.py  ${DATADIR}/${HOSTNAME}/${HOSTNAME}_1.pb ${DATADIR}/${HOSTNAME} /${HOSTNAME}1.bodyfile  
   
**Generate CSVs**  
  
5. psort -analysis tagging -o l2tcsv -w ${DATADIR}/${HOSTNAME}/${HOSTNAME}_1.csv ${DATADIR}/${HOSTNAME}/${HOSTNAME}_1.pb  
6. psort -analysis tagging --tagging-file /usr/share/plaso/tag_windows.txt -o l2tcsv -w ${DATADIR}/${HOSTNAME}/${HOSTNAME}_2.csv ${DATADIR}/${HOSTNAME}/${HOSTNAME}_2.pb  
