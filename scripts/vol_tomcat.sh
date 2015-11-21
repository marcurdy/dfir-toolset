if [ -n "`grep -i tomcat pslist.txt`" ]; then
  echo -n "Inspect: "
  grep -i tomcat filescan.txt | grep -i access_log | sed 's? \+? ?g'

  echo Looking for evidence of war files that could contain web shells
  awk -F: '{ print $2 }' strings.txt | grep "\.war" | sort | uniq -c | sort -n | grep webfile | tail
  echo ""
  echo If web shell found, detect argument from dl, up, and command sort grep
fi

