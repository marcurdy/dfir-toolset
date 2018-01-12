General threat detection

Namespace Collisions
* Internal domain names are not controlled externally
* Create a list of domains from DNS used by the clients for the org. Who owns their IP resolution?
* Search if wpad.dat reaches external organizations
* Search for domains outside com, net, org, gov, mil, edu

DNS/Proxy 
* Search for destinations of dynamic dns domains
* High volumes of NXDOMAIN errors could signify use of a domain generating algorithm (DGA)
* Search for typos of domains being accessed e.g. dnstwist
* Malicious domains often are set as uncategorized by proxies
  * Unsolicited outbound communication to the hostile domain with no referrer
  * Reputation of the domain

Source: Sqrrl Huntpedia PDF
