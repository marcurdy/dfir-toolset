**Timeline a mounted Windows partition**  
  
DATADIR=/data  
HOSTNAME=projectX  
MOUNTPOINT=/media/loop0p2  
 #TZ="-z CST6CDT"  
  
**Generate a timeline**  
1. log2timeline.py --status_view window --parsers webhist,win_gen --hashers MD5 ${TZ} ${DATADIR}/${HOSTNAME}.pb ${MOUNTPOINT}  
**Parse the MFT into a bodyfile format**  
2. analyzeMFT.py --bodyfull -b ${DATADIR}/${HOSTNAME}.bodyfile -f ${MOUNTPOINT}/\$MFT  
  
**Read the bodyfile into the existing Plaso file**  
3. log2timeline.py ${DATADIR}/${HOSTNAME}.pb ${DATADIR}/${HOSTNAME}.bodyfile  
  
**Post process the plaso timeline, apply various analyses, and output to t2tcsv to be fed to logstash**  
4. psort.py --analysis browser_search,chrome_extension,file_hashes,unique_domains_visited,windows_services,tagging --tagging-file /usr/share/plaso/tag_windows.txt ${TZ} -o l2tcsv -w ${DATADIR}/${HOSTNAME}.csv ${DATADIR}/${HOSTNAME}.pb  
