## Security Onion SW Relationships 

https://servername/elsa  
https://servername/squert  
  
sostat checks the status of all SecOnion's running processes. *EXTENSIVE!
soup performs the OS and application updates gracefully *AVOID APT-GET!

* Syslog-ng
  * configuration = /opt/elsa/contrib/securityonion/contrib/securityonion-syslog-ng.conf
  * Standard syslog input is also written to standard local logs

* OSSEC 
  * Monitors explicit logs in below config and writes analyzed findings to its own logs
  * Configuration = /var/ossec/etc
  * Rules = /var/ossec/rules
  * Alert Output = /var/ossec/logs

* Bro NSM
  * Listens on the raw network iface, processes input and writes to log files
  * Bro will decode several protocols, find protocol anomalies, capture certs, and plugin capable
  * Bro has an intel framework to detect and alert on IP, domains, MD5s, others
  * Configuration = /opt/bro/etc
  * Current log files = /nsm/bro/spool
  * Daily rotated log files = /nsm/bro/logs

* Bro and OSSEC logs on disk and incoming syslog is piped into this script:   
    * /opt/elsa/contrib/securityonion/contrib/securityonion-elsa-syslog-ng.sh

* Snort 
  * Captures all network traffic.  Alerts writen to disk in a unified2 format.
  * Snort configuration per interface = /etc/nsm/NAME-OF-SENSOR/snort*
  * Rules downloaded by Pulledpork = /etc/nsm/rules/downloaded.rules
  * Classification categories for rules: /etc/nsm/rules/classification.config
  * PulledPork defining all downloaded rules = /etc/nsm/pulledpork/pulledpork.conf
  ** Location where rule classifications are set to be ignored  
  ** Performs mapping of all rules  
  ** Holds location of IP reputation blacklists
  * Local snort rules = /etc/nsm/rules/local.rules
  * Manually rules update = sudo rule-update
  
* Sguil
  * Front-end to view Snort/Siricata alerts
  * barnyard2 is used to scrape the snort logs and write to squil's database.
  * tclsh scripts run to pull data from Snort, raw pcap, and OSSEC logs
  * Configuration = /etc/nsm/NAME-OF-SENSOR/*
  * squert is a frontend to squil data.

* ELSA
  * All data is piped directly into the engine from syslog-ng.
  * Analyses are written to mysql DB
  * Any regex against it is searched with sphinx search.
  * getpcap plug on ELSA shows full http transactions using capme
  * Config = /etc/elsa_node.conf
  * Logs   = /nsm/elsa/data/elsa/log
  * Mysql  = /nsm/elsa/data/elsa/mysql && /nsm/elsa/data/sphinx

* PCAP generation with netsniff
  * netsniff is writing to a dailylogs directory /nsm/sensor_data/<instance>/dailylogs/
  * Data is read by Bro and squil

* Network samples to tcpreplay are in /opt/samples
