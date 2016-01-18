## Security Onion SW Relationships 
* ELSA receives or queries local syslog data and stores into mysql.  Any regex against it is searched with sphinxsearch.
** getpcap plug on ELSA shows full http transactions using capme
* OSSEC collects syslog traffic and writes locally. A tcl daemon then writes it to the squil database.
* Snort packet captures and writes to a unified2 file. There's a rule-update command to update emerging threats rules.
* barnyard2 is used to scrape the raw snort logs and write to squil's database.
* Bro queries squil from a tcl daemon and writes to its own bro logs. bro entries are within sguil
** Bro will decode several protocols, find protocol anomalies (bad checksums), capture X.509 certs, and plugin capable.. 
** Bro has an intel framework to detect and alert on IP, domains, MD5s, others
* squil pulls in data from Snort for collection, analysis, and escalation of indications
* squert is a frontend to squil data.
* netsniff is writing to a dailylogs directory. I can't tell how this pcap generator fits into it all.
