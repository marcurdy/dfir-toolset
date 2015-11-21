if [ ! -f "shimcachemem" ]; then
  echo Run the shimcachemem module
else
  cat shimcachemem | awk '{ print $2 " " $4 " " $5 " " $6 " " $7 " " $8 " " $9 }' | sort
fi
