if [ -f "svcscan.txt" ]; then
  echo Searching for services without an associated binary
  grep -P4 -A1 SERVICE_RUNNING svcscan.txt | egrep 'Process ID:|Service Name: |Binary Path: ' | \
        sed ':a;$!N;s/\n/ \;/;ta;P;D' | sed 's?Process ID:?\nProcess ID:?g' | while read f; do
    if [ -n "$f" ] && [ -z "`echo $f | awk -F\; '{ print $3 }' | awk -F\: '{ print $2 }'`" ]; then
      echo No binary found for $f;
    fi
  done
else
  echo "svcscan.txt output from Volatility not found in current dir"
fi
