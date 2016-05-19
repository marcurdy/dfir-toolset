ls -1d /proc/fs/ext*/* /proc/fs/xfs*/* | awk -F/ '{ print $NF }' | while read PART; do
  echo /dev/$PART
done | while read DEV; do
  fls -m/ -r $DEV >> timeline.body
done

log2timeline.py timeline.pb timeline.body

psort.py -o l2tcsv -w timeline.csv timeline.pb

echo timeline.csv is ready

echo Don\'t forget to cleanup timeline.pb and timeline.body
