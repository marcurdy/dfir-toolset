# Completely a work in progress
# Don't use for now

if [ ! -d "$1" ]; then
  echo linuxMountAssist.sh <directory containing images>
  exit 1
fi

for file in `ls -1 $1`; do
  if [ -f "$1/$file" ]; then
    echo Analyzing $1/$file
  fi
done
FILETYPE=`file $1/$file | awk -F: '{ print $2 }' | awk '{ print $1 }'`
if [ "$FILETYPE" == "LVM2" ]; then
  echo losetup /dev/loopX
  echo run lvs to view newly available lv's to mount
elif [ "$FILETYPE" == "x86" ]; then
  mmls -Ma $1/$file | grep 'Linux \(' | while read FS; do
    OFFSET=$((`echo $FS | awk '{ print $3 }'`*512))
    echo losetup -o $OFFSET /dev/loopX
  done
  mmls -Ma $1/$file | grep 'Linux Logical' | while read FS; do
    OFFSET=$((`echo $FS | awk '{ print $3 }'`*512))
    echo losetup -o $OFFSET /dev/loopX
    echo run lvs to view newly available lv's to mount
  done
fi

CHROOTDIR="/mnt/CASE/root"
if [ "`mount | grep "$CHROOTDIR"` | wc -l" != 0 ]; then
  echo Manually mount the root FS to $CHROOTDIR first
  exit 1
fi
awk /VolGroup00/'{ print "mount " $1 " $CHROOTDIR/" $2 }' $CHROOTDIR/etc/fstab|bash

echo Convert your VMWareAddressSpace (vmsn) to raw with vol.py imagecopy.

