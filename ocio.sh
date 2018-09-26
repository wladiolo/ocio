#!/bin/bash
# script to automate public scan 
# 2018-09-03 v0.2
# author: wladiolo (github.com/wladiolo)

# how to use ocio
# ./ocio.sh [OPTIONS]
# -i <input>: input file with IPs or subnet, one per line (required)
# -m <mode>: mode of execution (required):
# 	1 found live IPs only
#	2 found live IPs and open ports
#	3 found live IPs, open ports and SSL/TLS information
# -pb <list>: comma separated list of black listed ports. Use "none" to match every port - no blacklist (required)
# -sb <list>: comma separated list of black listed services. Use "none" to match every service - no blacklist (required)
#  Please note that -pb and -sb are in AND
# 	-pb n1,n2 -sb s1,s2 match n1 AND s1, n1 AND s2, n2 AND s1, n2 AND s2
#	-pb none -sb s1,s2 match s1 or s2 AND every possible open port
#	-pb n1,n2 -sb none match n1 or n2 AND every possible open service
#   -pb none -sb none match all
# -s <email>: send summary to the specified email address (optional)
# -h print this help (optional)

#######################################################
## Colors for printing characters #####################
RED='\033[0;31m'
GREEN='\033[0;32m'
WHITE='\033[0;37m'
GREY='\033[1;30m'
NC='\033[0m' # no color

#######################################################
# parameter analysis ##################################
PARAMETERS=$@

# useful regexp
dirregex="([a-zA-Z0-9\.\-\/]+)ocio.sh"
Iregex="\-i\s([a-zA-Z0-9\.\-\/\_]+(\.[a-zA-Z]+|))"
Mregex="\-m\s([1-3])"
Sregex="\-s\s([a-z0-9._\-]+\@[a-z0-9.\-]+)"
Hregex="\-h"
PBregex1="\-pb\s+((\s*[0-9]+\s*\,*\s*)+[0-9]+)"
PBregex2="\-pb\s+none"
SBregex1="\-sb\s+((\s*[a-zA-Z0-9\-]+\s*\,*\s*)+[a-zA-Z0-9\-]+)"
SBregex2="\-sb\s+none"

# discovery of the execution directory
if [[ $0 =~ $dirregex ]]; then
	if [[ "${BASH_REMATCH[1]}" == "./" ]]; then
		execdir=$( pwd )"/"
	else
		execdir=$( pwd )"/"${BASH_REMATCH[1]}
	fi
else
	echo "Unknown error"
	exit
fi

# parameter analysis
if [[ $# -eq 0 || $PARAMETERS =~ $Hregex ]]; then
        echo -e "${WHITE}ocio usage:"
        echo -e "ocio.sh [OPTIONS]"
        echo -e "-i file: define input file with IPs or subnets to scan (required)" 
        echo -e "-m mode: define mode of operations (required)"
        echo -e "   mode=1: found live IPs only"
        echo -e "   mode=2: found live IPs and open ports"
        echo -e "   mode=3: found live IPs, open ports and perform SSL/TLS analysis"
        echo -e "-pb <list>: comma separated list of black listed ports. Use \"none\" to match every port - no blacklist (required)"
		echo -e "-sb <list>: comma separated list of black listed services. Use \"none\" to match every service - no blacklist (required)"
		echo -e " Please note that -pb and -sb are in AND"
		echo -e "   -pb n1,n2 -sb s1,s2 match n1 AND s1, n1 AND s2, n2 AND s1, n2 AND s2"
		echo -e "   -pb none -sb s1,s2 match s1 or s2 AND every possible open port"
		echo -e "   -pb n1,n2 -sb none match n1 or n2 AND every possible open service"
		echo -e "   -pb none -sb none match all"
        echo -e "-s email: send summary results to email address (optional)"
        echo -e "-h: print this help"
        echo -e "example: ./ocio.sh -i input.txt -m 3 -pb 25,443 -sb none -s pippo@pluto.com"
        echo -e "${NC}"
        exit
fi

if [[ $PARAMETERS =~ $Mregex ]]; then
	MODE=${BASH_REMATCH[1]}
else
	echo -e "${RED}[!] ${WHITE}Use option -m to specify the mode or -h to display help."
	exit
fi

if [[ $PARAMETERS =~ $Iregex ]]; then
	IPTOSCAN=${BASH_REMATCH[1]}
else
	echo -e "${RED}[!] ${WHITE}Use option -i to specify the input file or -h to display help."
	exit
fi

if [[ $PARAMETERS =~ $Sregex ]]; then
	RECIPIENT=${BASH_REMATCH[1]}
fi

if [[ $PARAMETERS =~ $PBregex1 ]]; then
	port_blacklist=${BASH_REMATCH[1]}
else
	if [[ $PARAMETERS =~ $PBregex2 ]]; then
		port_blacklist="none"
	else
		echo -e "${RED}[!] ${WHITE}Use option -pb to specify list of ports or -h to display help.${NC}"
		exit
	fi
fi

if [[ $PARAMETERS =~ $SBregex1 ]]; then
	service_blacklist=${BASH_REMATCH[1]}
else
	if [[ $PARAMETERS =~ $SBregex2 ]]; then
		service_blacklist="none"
	else
		echo -e "${RED}[!] ${WHITE}Use option -sb to specify list of ports or -h to display help.${NC}"
		exit
	fi
fi

#######################################################
## Print banner #######################################

echo -e "${WHITE} _____  ___  ____  _____    ${RED} __ _  _____  _ __  "
echo -e "${WHITE}(  _  )/ __)(_  _)(  _  )   ${RED}/ // )(  _  )( \\ \ "
echo -e "${WHITE} )(_)(( (__  _)(_  )(_)(   ${RED}< <( (  )(_)(  ) )> >"
echo -e "${WHITE}(_____)\___)(____)(_____)   ${RED}\__\\_)(_____)(_//_/ "
echo -e "${NC}"
echo -e "----------- ${GREEN}ocio v0.2  by wladiolo ${NC}-------------"
echo -e "------ ${RED}https://github.com/wladiolo/ocio ${NC}--------" 
echo ""

#######################################################
## Inputs and outputs #################################
# create output directory for current scan
count=0
SCANDIR="scan_"$( date +%Y%m%d )
while [ -d "$SCANDIR" ]; do
	count=$(($count+1))
	SCANDIR="scan_"$( date +%Y%m%d )"_$count"
done

mkdir $SCANDIR

# output log file with [i] data (ready to be sent via email)
LOGFILE=$SCANDIR"/log_"$( date +%Y%m%d )

# input file with IPs or subnet to scan
if [ -e $IPTOSCAN ]; then
	echo -e "${GREEN}[i] ${WHITE}Loaded $( cat $IPTOSCAN | wc -l ) entries from $IPTOSCAN"
	echo "[i] Loaded $( cat $IPTOSCAN | wc -l ) entries from $IPTOSCAN" >> $LOGFILE
else
	echo -e "${RED}[!] File $IPTOSCAN doesn't exist. Please verify and relaunch ocio."
	echo -e "${NC}"
	exit
fi

# output file that list all live hosts
LIVEHOSTS=$SCANDIR"/hosts_up_"$( date +%Y%m%d )

# output file that list all unique live IPs
LIVEIPS=$SCANDIR"/ips_up_"$( date +%Y%m%d )

# output file that lists all open ports
PORTDISCOVERY=$SCANDIR"/ports_discovery_"$( date +%Y%m%d )

# output file that lists all SSL/TLS information
TLSDISCOVERY=$SCANDIR"/tls_discovery_"$( date +%Y%m%d )

# output file with blacklist for open port/service results
BLACKLIST=$SCANDIR"/blacklist_summary_"$( date +%Y%m%d )

# output file with SSL/TLS analysis results
TLSANALYSIS=$SCANDIR"/tls_analysis_"$( date +%Y%m%d )

#######################################################
## nmap configurations ################################
# list of ports to check for port discovery (comma separated)
PORTLIST="21,22,23,25,53,80,110,123,139,143,161,179,389,443,445,465,514,554,587,636,993,995,1720,1935,2001,3333,3389,4001,5060,5061,6001,8009,8080,8081,8085,8090,8443,8900,9001,9080,9443,17990,17992,42828,50003,53620,56054,57180"

# list of ports to check for TLS/SSL information discovery (comma separated)
# TODO: create this list dinamically with port discovery using a special service blacklist
TLSPORTLIST="22,80,8080,443,8443,9443"

#######################################################
## Print summary information ##########################
echo -e "${GREEN}[i] ${WHITE}Start $( date +%Y-%m-%d@%H:%M:%S )"
echo "[i] Start $( date +%Y-%m-%d@%H:%M:%S )" >> $LOGFILE
echo -e "${GREEN}[i] ${WHITE}Scan results will be saved in $( pwd )/$SCANDIR" 
echo "[i] Scan results saved in $( pwd )/$SCANDIR" > $LOGFILE
if [[ ${#RECIPIENT} -gt 0 ]]; then
	echo -e "${GREEN}[i] ${WHITE}Summary results will be sent to $RECIPIENT"
else
	echo -e "${GREEN}[i] ${WHITE}No mail will be sent"
fi
case "$MODE" in
	"1")
		echo -e "${GREEN}[i] ${WHITE}Mode 1: live IPs discovering"
		echo "[i] Mode 1: live IPs discovering" >> $LOGFILE
	;;	
	"2")
		echo -e "${GREEN}[i] ${WHITE}Mode 2: live IPs and open ports discovering"
		echo "[i] Mode 2: live IPs and open ports discovering" >> $LOGFILE
	;;
	"3")
		echo -e "${GREEN}[i] ${WHITE}Mode 3: live IPs, open ports and SSL/TLS discovering"
		echo "[i] Mode 3: live IPs, open ports and SSL/TLS discovering" >> $LOGFILE
	;;
esac

#######################################################
## Discovery and analysis #############################
# launch nmap discovery of live IPs
echo -e "${GREEN}[+] ${WHITE}Discovering live IPs with nmap"
sudo nmap -sn -iL $IPTOSCAN -oG $LIVEHOSTS > /dev/null

# create a list of unique IPs and count the number of live IP
echo -e "${GREEN}[+] ${WHITE}Creating the list of unique IPs"
grep -P -o "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" $LIVEHOSTS | sort -u > $LIVEIPS
LIVEIPSNUM=$( cat $LIVEIPS | wc -l )
echo -e "${GREEN}[i] ${WHITE}Found $LIVEIPSNUM live IP(s)"
echo "[i] Found $LIVEIPSNUM live IP(s)" >> $LOGFILE

# launch nmap to discover open ports
# TODO: add UDP ports discovery
if [[ $MODE -ge 2 ]]; then
	echo -e "${GREEN}[+] ${WHITE}Discovering open ports on live IPs with nmap"
	echo -e "${GREEN}[i] ${WHITE}Port blacklist = $port_blacklist"
	echo -e "${GREEN}[i] ${WHITE}Service blacklist = $service_blacklist"
	sudo nmap -sS -Pn -R --max-retries 5 -iL $LIVEIPS -oA $PORTDISCOVERY -T4 > /dev/null
	# open port analysis based on blacklist
	"$execdir"ocio_open_port_analysis.sh -i $PORTDISCOVERY.nmap -pb $port_blacklist -sb $service_blacklist -o $SCANDIR
	#--- list open ports
	#for p in $( grep -P -o "^\d+" $PORTDISCOVERY.nmap | sort -u ) ; do
	#	echo -e "${GREEN}[i] ${WHITE}Found port $p open"
	#	echo "[i] Found port $p open" >> $LOGFILE
	#done
	#echo -e "${RED}[!] ${WHITE}Please see file $PORTDISCOVERY.nmap to match open ports to live IPs"
	#echo "[!] Please see file $PORTDISCOVERY.nmap to match open ports to live IPs" >> $LOGFILE
else
	echo -e "${GREEN}[i] ${WHITE}End $( date +%Y-%m-%d@%H:%M:%S )"
	echo "[i] End $( date +%Y-%m-%d@%H:%M:%S )" >> $LOGFILE
	echo -e "${NC}"
fi

# launch nmap to discover SSL/TLS information
if [[ $MODE -eq 3 ]]; then
	echo -e "${GREEN}[+] ${WHITE}Discovering TLS/SSL on live IPs with nmap"
	sudo nmap -iL $LIVEIPS --script ssl-cert,ssl-enum-ciphers -p$TLSPORTLIST --scan-delay 5s -oA $TLSDISCOVERY > /dev/null
	# ssl/tls analysis
	"$execdir"ocio_tls_discovery_analysis.sh -i $TLSDISCOVERY.nmap -o $SCANDIR
fi

#######################################################
## Send email #########################################
# TODO ...

#######################################################
## Final operations ###################################
echo -e "${GREEN}[i] ${WHITE}End $( date +%Y-%m-%d@%H:%M:%S )"
echo "[i] End $( date +%Y-%m-%d@%H:%M:%S )" >> $LOGFILE
echo -e "${NC}"
