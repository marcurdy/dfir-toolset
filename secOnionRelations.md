## Security Onion SW Relationships 

https://servername/elsa
https://servername/squert

sostat checks the status of all SecOnion's running processes.  

* PCAP generation with netsniff
  * netsniff is writing to a dailylogs directory /nsm/sensor_data/<instance>/dailylogs/
  * Data is read by Bro and squil

* Syslog-ng
  * configuration = /opt/elsa/contrib/securityonion/contrib/securityonion-syslog-ng.conf
  * Bro and OSSEC logs on disk and incoming syslog is piped into this script:   
    * /opt/elsa/contrib/securityonion/contrib/securityonion-elsa-syslog-ng.sh
  * Standard syslog input is also written to standard local logs

* OSSEC 
  * Monitors syslog-ng logs and writes analyzed findings to its own logs
  * Configuration = /var/ossec/etc
  * Alert Output = /var/ossec/logs

* Snort 
  * Captures all network traffic.  Alerts writen to disk in a unified2 format.
  * Configuration = /etc/nsm/NAME-OF-SENSOR/snort*
  * Rules downloaded by Pulledpork = /etc/nsm/rules/downloaded.rules
  * PulledPork modification of downloaded rules = /etc/nsm/pulledpork/
  * Local snort rules = /etc/nsm/rules/local.rules
  * Manually rules update = sudo rule-update
  
* Bro NSM
  * Listens on the raw network iface, processes input and writes to log files
  * Bro will decode several protocols, find protocol anomalies, capture certs, and plugin capable
  * Bro has an intel framework to detect and alert on IP, domains, MD5s, others
  * Configuration = /opt/bro/etc
  * Current log files = /nsm/bro/spool
  * Daily rotated log files = /nsm/bro/logs
  
* Sguil
  * barnyard2 is used to scrape the snort logs and write to squil's database.
  * tclsh scripts run to pull data from Snort, raw pcap, and OSSEC logs
  * Configuration = /etc/nsm/NAME-OF-SENSOR/*
  * squert is a frontend to squil data.

* ELSA
  * All data is piped directly into engine from syslog-ng.
  * Analyses are written to mysql DB
  * Any regex against it is searched with sphinx search.
  * getpcap plug on ELSA shows full http transactions using capme
  * Config = /etc/elsa_node.conf
  * Logs   = /nsm/elsa/data/elsa/log
  * Mysql  = /nsm/elsa/data/elsa/mysql && /nsm/elsa/data/sphinx
