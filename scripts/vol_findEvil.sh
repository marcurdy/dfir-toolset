#!/bin/sh
######################################
# Input = volatility extracted files
# 1) Check if file is a renamed PE
# 2) Check if the file is signed
# 3) If yes to 2) or 3),
#    i) send to ClamAV
#    i) send to VirusTotal
######################################

if [ -n "`ls *.img 2>/dev/null`" ]; 
  echo Found dumpfiles output. Renaming files to remove the .img suffix
  ls -1 *.img | while read f; do
    base=`echo $f | sed -e 's?\.img$??'`
    mv $f $base
  done
  echo Looking for exe\'s hidden in a non-exe named file
  missidentify * | tee saved
  echo Finding exe\'s without signed files
  ls -1 *.exe* | while read f; do 
    test=`signsrch $f 2>&1 | grep '0 signatures found'`
    if [ -n "$test" ]; then
      echo $f
    fi
  done
  missidentify * | tee -a saved
  sort -u saved > saved.txt
  rm -f saved

  echo Sending found files to clamscan. Reporting only infected.
  CLAMSCAN=`which clamscan`
  if [ -f $CLAMSCAN ]; then
    clamscan -i -f saved.txt
  fi

  echo Send found files to VT. Reporting only infected.
  cat saved.txt | while read f; do
    sum=`md5sum $f | awk '{ print $1 }'`
    echo $f
    vtTool.py -hash $sum 2>&1 | grep 'Most frequent word:' | grep -v 'count=0'
  done
  rm saved
else
  echo No dumpfiles output found in currdir
fi

