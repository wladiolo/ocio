#!/bin/bash
# script to automate public scan 
# module for open port analysys
# 2018-09-03 v0.2
# author: wladiolo (github.com/wladiolo)

# how to use ocio_open_port_analysis
# ./ocio_open_port_analysis.sh [OPTIONS]
# -i <file>: nmap results of a port scan in .nmap format (required)
# -pb <list>: comma separated list of black listed ports. Use "none" to match every port - no blacklist (required)
# -sb <list>: comma separated list of black listed services. Use "none" to match every service - no blacklist (required)
#  Please note that -pb and -sb are in AND
# 	-pb n1,n2 -sb s1,s2 match n1 AND s1, n1 AND s2, n2 AND s1, n2 AND s2
#	-pb none -sb s1,s2 match s1 or s2 AND every possible open port
#	-pb n1,n2 -sb none match n1 or n2 AND every possible open service
#   -pb none -sb none match all
# -o <dir>: output directory (optional)
# -h print this help (optional)

#######################################################
## Colors for printing characters #####################
RED='\033[0;31m'
GREEN='\033[0;32m'
WHITE='\033[0;37m'
GREY='\033[1;30m'
NC='\033[0m' # no color

#######################################################
## Functions ##########################################
print_on_terminal () {
	# print on terminal lines that match ports or services blacklist
	# $1 = IP
	# $2 = port
	# $3 = service
	# $4 = protocol
	# $5 = p(ort) or s(ervice) blacklist
	if [[ "$5" == "p" ]]; then
		echo -e -n "${RED}[!] ${WHITE}$1"
		numspaces=$((15 - ${#1}))
		while [ $numspaces -gt 0 ]; do
			echo -e -n " "
			numspaces=$(($numspaces - 1))
		done
		echo -e -n " ${RED}$2${WHITE}"
		numspaces=$((5 - ${#2}))
		while [ $numspaces -gt 0 ]; do
			echo -e -n " "
			numspaces=$(($numspaces - 1))
		done
		echo -e -n " $4"
		echo -e " $3${NC}"
	fi
	if [[ "$5" == "s" ]]; then
		echo -e -n "${RED}[!] ${WHITE}$1"
		numspaces=$((15 - ${#1}))
		while [ $numspaces -gt 0 ]; do
			echo -e -n " "
			numspaces=$(($numspaces - 1))
		done
		echo -e -n " $2"
		numspaces=$((5 - ${#2}))
		while [ $numspaces -gt 0 ]; do
			echo -e -n " "
			numspaces=$(($numspaces - 1))
		done
		echo -e -n " $4"
		echo -e " ${RED}$3${NC}"
	fi
	if [[ "$5" == "a" ]]; then
		echo -e -n "${GREY}[i] $1"
		numspaces=$((15 - ${#1}))
		while [ $numspaces -gt 0 ]; do
			echo -e -n " "
			numspaces=$(($numspaces - 1))
		done
		echo -e -n " $2"
		numspaces=$((5 - ${#2}))
		while [ $numspaces -gt 0 ]; do
			echo -e -n " "
			numspaces=$(($numspaces - 1))
		done
		echo -e -n " $4"
		echo -e " $3"
	fi
	if [[ "$5" == "ps" ]]; then
		echo -e -n "${RED}[!] ${WHITE}$1"
		numspaces=$((15 - ${#1}))
		while [ $numspaces -gt 0 ]; do
			echo -e -n " "
			numspaces=$(($numspaces - 1))
		done
		echo -e -n " ${RED}$2${WHITE}"
		numspaces=$((5 - ${#2}))
		while [ $numspaces -gt 0 ]; do
			echo -e -n " "
			numspaces=$(($numspaces - 1))
		done
		echo -e -n " $4"
		echo -e " ${RED}$3${NC}"
	fi
}

print_header () {
	# print header in log file
	# $1 = logfile
	header="BL IP              Port  Prot Service"
	echo "$header" > $1
}

print_in_file () {
	# print in file lines that match ports or services blacklist
	# $1 = IP
	# $2 = port
	# $3 = service
	# $4 = protocol
	# $5 = p(ort) or s(ervice) blacklist
	# $6 = filename
	if [[ "$5" == "p" ]]; then
		echo -n "P  $1" >> $6
		numspaces=$((15 - ${#1}))
		while [ $numspaces -gt 0 ]; do
			echo -n " " >> $6
			numspaces=$(($numspaces - 1))
		done
		echo -n " $2" >> $6
		numspaces=$((5 - ${#2}))
		while [ $numspaces -gt 0 ]; do
			echo -n " " >> $6
			numspaces=$(($numspaces - 1))
		done
		echo -n " $4 " >> $6
		echo " $3" >> $6
	fi
	if [[ "$5" == "s" ]]; then
		echo -n "S  $1" >> $6
		numspaces=$((15 - ${#1}))
		while [ $numspaces -gt 0 ]; do
			echo -n " " >> $6
			numspaces=$(($numspaces - 1))
		done
		echo -n " $2" >> $6
		numspaces=$((5 - ${#2}))
		while [ $numspaces -gt 0 ]; do
			echo -n " " >> $6
			numspaces=$(($numspaces - 1))
		done
		echo -n " $4 " >> $6
		echo " $3" >> $6
	fi
	if [[ "$5" == "a" ]]; then
		echo -n "NB $1" >> $6
		numspaces=$((15 - ${#1}))
		while [ $numspaces -gt 0 ]; do
			echo -n " " >> $6
			numspaces=$(($numspaces - 1))
		done
		echo -n " $2" >> $6
		numspaces=$((5 - ${#2}))
		while [ $numspaces -gt 0 ]; do
			echo -n " " >> $6
			numspaces=$(($numspaces - 1))
		done
		echo -n " $4 " >> $6
		echo " $3" >> $6
	fi
	if [[ "$5" == "ps" ]]; then
		echo -n "PS $1" >> $6
		numspaces=$((15 - ${#1}))
		while [ $numspaces -gt 0 ]; do
			echo -n " " >> $6
			numspaces=$(($numspaces - 1))
		done
		echo -n " $2" >> $6
		numspaces=$((5 - ${#2}))
		while [ $numspaces -gt 0 ]; do
			echo -n " " >> $6
			numspaces=$(($numspaces - 1))
		done
		echo -n " $4 " >> $6
		echo " $3" >> $6
	fi
}

#######################################################
# parameter analysis ##################################
PARAMETERS=$@

Iregex="\-i\s+([a-zA-Z0-9\.\-\/\_]+(\.[a-zA-Z]+|))"
PBregex1="\-pb\s+((\s*[0-9]+\s*\,*\s*)+[0-9]+)"
PBregex2="\-pb\s+none"
SBregex1="\-sb\s+((\s*[a-zA-Z0-9\-]+\s*\,*\s*)+[a-zA-Z0-9\-]+)"
SBregex2="\-sb\s+none"
Oregex="\-o\s+([a-zA-Z0-9\-\_\/]+)"
Hregex="\-h"

if [[ $# -eq 0 || $PARAMETERS =~ $Hregex ]]; then
        echo -e "${WHITE}ocio usage:"
        echo -e "ocio_open_port_analysis.sh [OPTIONS]"
        echo -e "-i file: nmap results of a port scan in .nmap format (required)"
        echo -e "-pb <list>: comma separated list of black listed ports. Use \"none\" to match all ports - no blacklist (required)"
        echo -e "-sb <list>: comma separated list of black listed services. Use \"none\" to match all services - no blacklist (required)"
        echo -e "  Please note that -pb and -sb are in AND"
		echo -e " 	-pb n1,n2 -sb s1,s2 match n1 AND s1, n1 AND s2, n2 AND s1, n2 AND s2"
		echo -e "	-pb none -sb s1,s2 match s1 or s2 AND every possible open port"
		echo -e "	-pb n1,n2 -sb none match n1 or n2 AND every possible open service"
		echo -e "   -pb none -sb none match all"
		echo -e "-o <dir>: output directory (optional)"
        echo -e "-h: print this help"
        echo -e "example: ./ocio_open_port_analysis.sh -i input.nmap -pb 25,445,3389 -sb pop,smtp,rdp -o /home/wladiolo/scan"
        echo -e "${NC}"
        exit
fi

if [[ $PARAMETERS =~ $Iregex ]]; then
	INPUTFILE=${BASH_REMATCH[1]}
	if [ ! -e $INPUTFILE ]; then
		echo -e "${RED}[!] File $INPUTFILE doesn't exist. Please verify and relaunch the program."
		echo -e "${NC}"
		exit
	fi
else
	echo -e "${RED}[!] ${WHITE}Use option -i to specify the input file or -h to display help.${NC}"
	exit
fi

if [[ $PARAMETERS =~ $PBregex1 ]]; then
	PORTBLACKLISTRAW=${BASH_REMATCH[1]}
	# transform the list in array
	port_blacklist=$( echo ${PORTBLACKLISTRAW[@]//,/ } )
	port_all="false"
else
	if [[ $PARAMETERS =~ $PBregex2 ]]; then
		port_all="true"
	else
		echo -e "${RED}[!] ${WHITE}Use option -pb to specify list of ports or -h to display help.${NC}"
		exit
	fi
fi

if [[ $PARAMETERS =~ $SBregex2 ]]; then
	service_all="true"
else
	if [[ $PARAMETERS =~ $SBregex1 ]]; then
		SERVICEBLACKLISTRAW=${BASH_REMATCH[1]}
		# transform the list in array
		service_blacklist=$( echo ${SERVICEBLACKLISTRAW[@]//,/ } )
		service_all="false"	
	else
		echo -e "${RED}[!] ${WHITE}Use option -sb to specify list of services or -h to display help.${NC}"
		exit
	fi
fi

if [[ $PARAMETERS =~ $Oregex ]]; then
	OUTPUTDIR=${BASH_REMATCH[1]}
else
	OUTPUTDIR="."
fi

#######################################################
## Regular expression #################################
# regexp for capturing interesting open ports and or services (blacklist) and other info
ip_regex1="Nmap\sscan\sreport\sfor\s[a-zA-Z0-9.\-]+\s\(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
ip_regex2="Nmap\sscan\sreport\sfor\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
open_port_regex="([0-9]+)\/([a-z]+)\s+open\s+([a-zA-Z0-9\-]+)"
# template of blacklist rules
# port blacklist match exactly the port number, only open ports
port_blacklist_regex="\/(\w+)\s+open\s+([a-zA-Z0-9\-]+)"

# service blacklist match the string in service name, only open ports
# e.g. if in the blacklist is present "http", the rule will match "http", "https", "http-proxy"
# TODO: let user choose if he want an exact match or a partial match
service_blacklist_regex1="([0-9]+)\/(\w+)\s+open\s+"
service_blacklist_regex2="[a-zA-Z0-9\-\.]*"

# port and service blacklist match exactly the port number (only open ports) and the string in service name
port_service_blacklist_regex1="\/(\w+)\s+open\s+"
port_service_blacklist_regex2="[a-zA-Z0-9\-\.]*"

# no blacklist regex
no_blacklist_regex="([0-9]+)\/(\w+)\s+open\s+([a-zA-Z0-9\-]+)"

#######################################################
## Log file ###########################################
logfile="$OUTPUTDIR/open_port_summary.log"
print_header $logfile

#######################################################
## Analysis operations ################################
IP=""
port=""
protocol=""
service=""
while read -r line
do
	# regex matching
	if [[ $line =~ $ip_regex1 || $line =~ $ip_regex2 ]]; then
		IP=${BASH_REMATCH[1]}
		count_match=1
	fi
	
	if [[ $line =~ $open_port_regex ]]; then
		# -pb all -sb all
		if [[ $port_all == "true" && $service_all == "true" ]]; then
			port=${BASH_REMATCH[1]}
			protocol=${BASH_REMATCH[2]}
			service=${BASH_REMATCH[3]}
			print_on_terminal $IP $port $service $protocol "a"
			print_in_file $IP $port $service $protocol "a" $logfile
		fi
		# -pb p1,p2,.. -sb all
		if [[ $port_all == "false" && $service_all == "true" ]]; then
			for p in ${port_blacklist[@]}; do
				regex="^"$p$port_blacklist_regex #"^" needed to match exactly the port specified
				if [[ $line =~ $regex ]]; then
					protocol=${BASH_REMATCH[1]}
					service=${BASH_REMATCH[2]}
					print_on_terminal $IP $p $service $protocol "p"
					print_in_file $IP $p $service $protocol "p" $logfile
					break
				fi
			done
		fi
		# -pb all -sb s1,s2,...
		if [[ $port_all == "true" && $service_all == "false" ]]; then
			for s in ${service_blacklist[@]}; do
				regex=$service_blacklist_regex1"("$service_blacklist_regex2$s$service_blacklist_regex2")" #needed to match part of the service name
				if [[ $line =~ $regex ]]; then
					port=${BASH_REMATCH[1]}
					protocol=${BASH_REMATCH[2]}
					service=${BASH_REMATCH[3]}
					print_on_terminal $IP $port $service $protocol "s"
					print_in_file $IP $port $service $protocol "s" $logfile
					break
				fi
			done
		fi
		# -pb p1,p2,... -sb s1,s2,...
		if [[ $port_all == "false" && $service_all == "false" ]]; then
			for p in ${port_blacklist[@]}; do
				for s in ${service_blacklist[@]}; do
					regex="^"$p$port_service_blacklist_regex1"("$port_service_blacklist_regex2$s$port_service_blacklist_regex2")" #needed to match part of the service name + "^" needed to match exactly the port specified
					if [[ $line =~ $regex ]]; then
						protocol=${BASH_REMATCH[1]}
						service=${BASH_REMATCH[2]}
						print_on_terminal $IP $p $service $protocol "ps"
						print_in_file $IP $p $service $protocol "ps" $logfile
						break
					fi
				done
			done
		fi
	fi
	
done < "$INPUTFILE" 

# closing operations
echo -e -n "${NC}"
