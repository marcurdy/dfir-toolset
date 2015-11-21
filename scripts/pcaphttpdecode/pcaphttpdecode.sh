#!/bin/sh

 SDIR="individual_streams"
 SCRIPTDIR=$( cd $(dirname $0) ; pwd -P )

### reassembly of packets + splitting in smaller reassembled pcaps.
 tshark -o 'tcp.desegment_tcp_streams:TRUE' -r "$1" -T fields -e tcp.stream | sort -un | tr '\n' ' ' > streams
 rm -rf ${SDIR}; mkdir ${SDIR}
 for x in `cat streams`; do 
    tshark -F pcap -r "$1" -w "${SDIR}/${x}.pcap" tcp.stream eq $x
    echo "Finished stream ${x}"
  done
 rm streams

 cd ${SDIR}
# carve out and decompress javascript from http dumps
 for i in *.pcap; do 
   python $SCRIPTDIR/pcap2httpflow.py "$i" 
 done | tee urls.txt | grep -B2 "${SDIR}.*js"

 for i in *.js; do
    echo "$i"; cat $SCRIPTDIR/inject.js "$i" | js > "$i.dec"
    dos2unix "$i.dec"
  done

 ls -1  *.dec | while read f; do
   cat $f |  grep -oE 'unescape\(\"[^\"]{50}[^\"]*\"' | \
   cut -d '"' -f2 | python $SCRIPTDIR/s2b.py >> `mktemp -q shellcode.XXXXXX`
 done
 find . -size 0c -exec rm {} \;
 for file in `ls -1 shellcode.*`; do
   md5sum $file
 done

for i in shellcode.*; do sctest -Svs 1000000 < "$i" > "$i.decoded"; done
grep -H 'not mapped' *.decoded | awk -F: '{ print $1 }' | xargs rm
rm *.js *.pcap
