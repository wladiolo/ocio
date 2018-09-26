# ocio

*ocio* is a very simple program that uses nmap functionalities to monitor a range of IPs.

## Scenario

*ocio* wants to help people that need to monitor a range of IPs and want to be alerted if some specific port or services are open.

*ocio* can also report on the status of SSL/TLS.

## How to use ocio 

*ocio* is made of three scripts that perform different operations.

### ocio.sh
It carries out the main functionalities of ocio (find live IPs, scan or open ports, scan SSL/TLS).

```
./ocio.sh [OPTIONS]
 -i <input>: input file with IPs or subnet, one per line (required)
 -m <mode>: mode of execution (required):
 	1 found live IPs only
	2 found live IPs and open ports
	3 found live IPs, open ports and SSL/TLS information
 -pb <list>: comma separated list of black listed ports. Use "none" to match every port - no blacklist (required)
 -sb <list>: comma separated list of black listed services. Use "none" to match every service - no blacklist (required)
  Please note that -pb and -sb are in AND
 	-pb n1,n2 -sb s1,s2 match n1 AND s1, n1 AND s2, n2 AND s1, n2 AND s2
	-pb none -sb s1,s2 match s1 or s2 AND every possible open port
	-pb n1,n2 -sb none match n1 or n2 AND every possible open service
   -pb none -sb none match all
 -s <email>: send summary to the specified email address (optional)
 -h print this help (optional)
```
