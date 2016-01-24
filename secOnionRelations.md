## Security Onion SW Relationships 

Run sostat check the status of all SecOnion's running processes.  

* PCAP generation with netsniff
  * netsniff is writing to a dailylogs directory /nsm/sensor_data/<instance>/dailylogs/

* OSSEC 
  * collects syslog traffic and writes analyzed findings to its own logs

* Snort 
  * Full PCAP captures and writen to disk in a unified2 file.
  * Rules downloaded by Pulledpork = /etc/nsm/rules/downloaded.rules
  * PulledPork modification of downloaded rules = /etc/nsm/pulledpork/
  * Local snort rules = /etc/nsm/rules/local.rules
  * Manually rules update = sudo rule-update
  * Snort/Squil/Barnyard Sensor configurations =  /etc/nsm/NAME-OF-SENSOR/
   
* Bro NSM
  * Listens on the raw network iface, processes input and writes to log files
  * Bro will decode several protocols, find protocol anomalies, capture certs, and plugin capable
  * Bro has an intel framework to detect and alert on IP, domains, MD5s, others
  * Configuration = /opt/bro/etc
  * Current log files = /nsm/bro/spool
  * Daily rotated log files = /nsm/bro/logs
  
* Syslog-ng
  * configuration = /opt/elsa/contrib/securityonion/contrib/securityonion-syslog-ng.conf
  * Bro and OSSEC written logs and general syslog is piped into a script:   
    * /opt/elsa/contrib/securityonion/contrib/securityonion-elsa-syslog-ng.sh
  * Standard syslog input is also written to standard local logs

* SQUIL
  * barnyard2 is used to scrape the raw snort logs and write to squil's database.
  * tclsh scripts run to pull data from Snort, raw pcap, and OSSEC logs
  * squert is a frontend to squil data.

* ELSA
  * All data is piped directly into engine from syslog-ng.
  * Analyses are written to mysql DB
  * Any regex against it is searched with sphinx search.
  * getpcap plug on ELSA shows full http transactions using capme
  * Config = /etc/elsa_node.conf
  * Logs   = /nsm/elsa/data/elsa/log
  * Mysql  = /nsm/elsa/data/elsa/mysql && /nsm/elsa/data/sphinx
