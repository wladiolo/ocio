#!/bin/bash
# script to automate public scan 
# module for SSL/TLS analysys
# 2018-09-11 v0.2
# author: wladiolo (github.com/wladiolo)

# how to use ocio_tls_discovery_analysis
# ./ocio_open_port_analysis.sh [OPTIONS]
# -i <file>: nmap results of a SSL/TLS scan in .nmap format (required)
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
# function to compare a date with today
compare_date () {
	# $1 is the expire date
	if [[ "$1" == "unknown" ]]; then
		cert_expired=1
	else
		today=$( date +%Y-%m-%d )
		today_sec=$( date -d $today +%s )
		expire_sec=$( date -d $1 +%s )
		if [[ $expire_sec -ge $today_sec ]]; then
				cert_expired=0
		else
				cert_expired=1
		fi
	fi
    return $cert_expired
}
# function to print summary header - for print_on_terminal function
print_header () {
	# $1 is the log filename
	header="IP              port  SSLv2 SSLv3 TLS1.0 TLS1.1 TLS1.2 TLS1.3 Cert    expire     commonName"
	echo "$header" > $1
}

# function for printing summary info in a log file
print_in_file () {

	# string to print
	# $1              $2    $5    $6    $7     $8     $9     $10            $4         $3 
	# IP              port  SSLv2 SSLv3 TLS1.0 TLS1.1 TLS1.2 TLS1.3 Cert    expire     commonName
	# ddd.ddd.ddd.ddd ddddd OFF   ON    ON     ON     OFF    OFF    Expired dddd-dd-dd wwwwwwwwwwwwwwwwwwwww+
	# ddd.ddd.ddd.ddd ddddd ON    OFF   OFF    ON     OFF    OFF    Valid   dddd-dd-dd wwwwwwwwwwwwwwwwwwwww+
	# $11 is the log filename
	# ON means that protocol is active 
	# OFF means that protocol is inactive
	# Expired means the certificate is expired
	# Valid   means the certificate is still valid

	echo -n "$1" >> ${11}
	numspaces=$((15 - ${#1}))
	while [ $numspaces -gt 0 ]; do
		echo -n " " >> ${11}
		numspaces=$(($numspaces - 1))
	done
	echo -n " $2" >> ${11}
	numspaces=$((5 - ${#2}))
	while [ $numspaces -gt 0 ]; do
		echo -n " " >> ${11}
		numspaces=$(($numspaces - 1))
	done
	if [[ $5 -eq 1 ]]; then
		echo -n " ON   " >> ${11}
	else
		echo -n " OFF  " >> ${11}
	fi
	if [[ $6 -eq 1 ]]; then
		echo -n " ON   " >> ${11}
	else
		echo -n " OFF  " >> ${11}
	fi
	if [[ $7 -eq 1 ]]; then
		echo -n " ON    " >> ${11}
	else
		echo -n " OFF   " >> ${11}
	fi
	if [[ $8 -eq 1 ]]; then
		echo -n " ON    " >> ${11}
	else
		echo -n " OFF   " >> ${11}
	fi
	if [[ $9 -eq 1 ]]; then
		echo -n " ON    " >> ${11}
	else
		echo -n " OFF   " >> ${11}
	fi
	if [[ ${10} -eq 1 ]]; then
		echo -n " ON    " >> ${11}
	else
		echo -n " OFF   " >> ${11}
	fi
	# verify if certificate is expired
	compare_date $4
	if [[ $cert_expired -eq 1 ]]; then
		echo -n " Expired" >> ${11}
	else
		echo -n " Valid  " >> ${11}
	fi
	echo -n " $4" >> ${11}
	numspaces=$((10 - ${#4}))
	while [ $numspaces -gt 0 ]; do
		echo -n " " >> ${11}
		numspaces=$(($numspaces - 1))
	done
	if [[ "$3" == "unknown" ]]; then
		echo " unknown certificate name" >> ${11}
	else	
		echo " $3" >> ${11}
	fi
}

# function for printing info on the terminal
print_on_terminal () {

	# string to print
	# $1              $2    $5    $6    $7     $8     $9     $10    $4         $3 
	# 1.2.101.202     443   SSLv2 SSLv3 TLS1.0 TLS1.1 TLS1.2 TLS1.3 2018-09-26 secure.fasthosting.it
	# ddd.ddd.ddd.ddd ddddd wwwww wwwww wwwwww wwwwww wwwwww wwwwww dddd-dd-dd wwwwwwwwwwwwwwwwwwwww+
	# IP address always printed in white
	# port always printed in white
	# when SSLv2, SSLv3, TLS1.0 and TLS1.1 are active they will be printed in red; when non active they will be printed in grey
	# when TLS1.2 and TLS1.3 are active they will be printed in green; when non active they will be printed in grey
	# when cert is expired, expiration date will be printed in red; when valid, expiration date will be printed in green
	# commonName always printed in white    

	echo -e -n "${WHITE}$1"
	numspaces=$((15 - ${#1}))
	while [ $numspaces -gt 0 ]; do
		echo -e -n " "
		numspaces=$(($numspaces - 1))
	done
	echo -e -n " ${WHITE}$2"
	numspaces=$((5 - ${#2}))
	while [ $numspaces -gt 0 ]; do
		echo -e -n " "
		numspaces=$(($numspaces - 1))
	done
	if [[ $5 -eq 1 ]]; then
		echo -e -n " ${RED}SSLv2"
	else
		echo -e -n " ${GREY}SSLv2"
	fi
	if [[ $6 -eq 1 ]]; then
		echo -e -n " ${RED}SSLv3"
	else
		echo -e -n " ${GREY}SSLv3"
	fi
	if [[ $7 -eq 1 ]]; then
		echo -e -n " ${RED}TLSv1.0"
	else
		echo -e -n " ${GREY}TLSv1.0"
	fi
	if [[ $8 -eq 1 ]]; then
		echo -e -n " ${RED}TLSv1.1"
	else
		echo -e -n " ${GREY}TLSv1.1"
	fi
	if [[ $9 -eq 1 ]]; then
		echo -e -n " ${GREEN}TLSv1.2"
	else
		echo -e -n " ${GREY}TLSv1.2"
	fi
	if [[ ${10} -eq 1 ]]; then
		echo -e -n " ${GREEN}TLSv1.3"
	else
		echo -e -n " ${GREY}TLSv1.3"
	fi
	# verify if certificate is expired
	compare_date $4
	if [[ $cert_expired -eq 1 ]]; then
		echo -e -n " ${RED}$4"
		count_expired=$(($count_expired + 1))
	else
		echo -e -n " ${GREEN}$4"
	fi
	numspaces=$((10 - ${#4}))
	while [ $numspaces -gt 0 ]; do
		echo -e -n " "
		numspaces=$(($numspaces - 1))
	done
	if [[ "$3" == "unknown" ]]; then
		echo -e " ${RED}unknown certificate name"
	else	
		echo -e " ${WHITE}$3${NC}"
	fi
}

#######################################################
# parameter analysis ##################################
PARAMETERS=$@

Iregex="\-i\s+([a-zA-Z0-9\.\-\/\_]+(\.[a-zA-Z]+|))"
Oregex="\-o\s+([a-zA-Z0-9\-\_\/]+)"
Hregex="\-h"

if [[ $# -eq 0 || $PARAMETERS =~ $Hregex ]]; then
        echo -e "${WHITE}ocio usage:"
        echo -e "ocio_tls_discovery_analysis.sh [OPTIONS]"
        echo -e "-i file: nmap results of a SSL/TLS scan in .nmap format (required)"
		echo -e "-o <dir>: output directory (optional)"
        echo -e "-h: print this help"
        echo -e "example: ./ocio_tls_discovery_analysis.sh -i input.nmap -o /home/wladiolo/scan"
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

if [[ $PARAMETERS =~ $Oregex ]]; then
	OUTPUTDIR=${BASH_REMATCH[1]}
else
	OUTPUTDIR="."
fi

#######################################################
## Regular expression #################################
ip_regex1="Nmap\sscan\sreport\sfor\s[a-zA-Z0-9.\-]+\s\(([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
ip_regex2="Nmap\sscan\sreport\sfor\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
openport_regex="([0-9]+)\/[a-z]+\s+open"
name_regex="\|\sssl-cert\:\sSubject:\scommonName\=([a-z0-9\.\*\-]+)"
expire_regex="\|\sNot\svalid\safter\:\s+([0-9]+\-[0-9]+\-[0-9]+)\T[0-9]+\:[0-9]+\:[0-9]"
SSL2_regex="\|\s+SSLv2"
SSL3_regex="\|\s+SSLv3"
TLS10_regex="\|\s+TLSv1\.0"
TLS11_regex="\|\s+TLSv1\.1"
TLS12_regex="\|\s+TLSv1\.2"
TLS13_regex="\|\s+TLSv1\.3"
least_regex="\|\_\s+least\sstrength"

#######################################################
## Log file ###########################################
logfile="$OUTPUTDIR/tls_analysis_summary.log"
print_header $logfile

#######################################################
## Analysis operations ################################
IP=""
PORT=""
NAME="unknown"
EXPIRE="unknown"
SSL2=0
SSL3=0
TLS10=0
TLS11=0
TLS12=0
TLS13=0
count_SSL2=0
count_SSL3=0
count_TLS10=0
count_TLS11=0
count_TLS12=0
count_TLS13=0
count_match=0
count_expired=0
count_cert=0
count_port=0
ok_print=0
while read -r line
do
	# print a line if all the desired information are present
	if [[ $count_match -gt 0 && $ok_print -eq 1 ]]; then
		print_on_terminal $IP $PORT $NAME $EXPIRE $SSL2 $SSL3 $TLS10 $TLS11 $TLS12 $TLS13
		print_in_file $IP $PORT $NAME $EXPIRE $SSL2 $SSL3 $TLS10 $TLS11 $TLS12 $TLS13 $logfile
		# re-initialize variables for a new line
		ok_print=0
		PORT=""
		NAME="unknown"
		EXPIRE="unknown"
		SSL2=0
		SSL3=0
		TLS10=0
		TLS11=0
		TLS12=0
		TLS13=0
	fi
	
	# regex matching
	if [[ $line =~ $ip_regex1 || $line =~ $ip_regex2 ]]; then
		IP=${BASH_REMATCH[1]}
		count_match=1
		continue
	fi
	if [[ $line =~ $openport_regex ]]; then
        PORT=${BASH_REMATCH[1]}
		count_match=$(($count_match + 1))
		continue
        fi
	if [[ $line =~ $name_regex ]]; then
        NAME=${BASH_REMATCH[1]}
        count_cert=$(($count_cert + 1))
		count_match=$(($count_match + 1))
		continue
        fi
	if [[ $line =~ $expire_regex ]]; then
        EXPIRE=${BASH_REMATCH[1]}
		count_match=$(($count_match + 1))
		continue
        fi
	if [[ $line =~ $SSL2_regex ]]; then
        SSL2=1
		count_match=$(($count_match + 1))
		count_SSL2=$(($count_SSL2 + 1))
		continue
	fi
	if [[ $line =~ $SSL3_regex ]]; then
        SSL3=1
		count_match=$(($count_match + 1))
		count_SSL3=$(($count_SSL3 + 1))
		continue
        fi
	if [[ $line =~ $TLS10_regex ]]; then
        TLS10=1
		count_match=$(($count_match + 1))
		count_TLS10=$(($count_TLS10 + 1))
		continue
        fi
	if [[ $line =~ $TLS11_regex ]]; then
        TLS11=1
		count_match=$(($count_match + 1))
		count_TLS11=$(($count_TLS11 + 1))
		continue
        fi
	if [[ $line =~ $TLS12_regex ]]; then
        TLS12=1
		count_match=$(($count_match + 1))
		count_TLS12=$(($count_TLS12 + 1))
		continue
        fi
	if [[ $line =~ $TLS13_regex ]]; then
        TLS13=1
		count_match=$(($count_match + 1))
		count_TLS13=$(($count_TLS13 + 1))
		continue
        fi
	if [[ $line =~ $least_regex ]]; then
        count_match=$(($count_match + 1))
        count_port=$(($count_port + 1))
        ok_print=1
        continue
        fi

done < "$INPUTFILE" 

# print latest information collected
if [[ $count_match -gt 0 && $ok_print -eq 1 ]]; then
	print_on_terminal $IP $PORT $NAME $EXPIRE $SSL2 $SSL3 $TLS10 $TLS11 $TLS12 $TLS13
	print_in_file $IP $PORT $NAME $EXPIRE $SSL2 $SSL3 $TLS10 $TLS11 $TLS12 $TLS13 $logfile
	ok_print=0
fi

# print statistics 
#echo -e "${WHITE}++++++++++++++++++++++ Statistics ++++++++++++++++++++++"
#echo "++++++++++++++++++++++ Statistics ++++++++++++++++++++++" >> $logfile
#echo -e "${GREEN}[i] ${WHITE}Found $count_cert certificate(s)"
#echo "[i] Found $count_cert certificate(s)"  >> $logfile
#echo -e "${GREEN}[i] ${WHITE}Found $count_port port(s) open"
#echo "[i] Found $count_port port(s) open" >> $logfile
#if [[ $count_expired -gt 0 ]]; then
#	echo -e "${GREEN}[i] ${WHITE}Found ${RED}$count_expired expired certificate(s)"
#	echo -e "[i] Found $count_expired expired certificate(s)" >> $logfile
#fi
#if [[ $count_SSL2 -gt 0 ]]; then 
#	echo -e "${GREEN}[i] ${WHITE}Found ${RED}$count_SSL2 services with SSLv2 enabled"
#	echo "[i] Found $count_SSL2 services with SSLv2 enabled" >> $logfile
#fi
#if [[ $count_SSL3 -gt 0 ]]; then
#	echo -e "${GREEN}[i] ${WHITE}Found ${RED}$count_SSL3 services with SSLv3 enabled"
#	echo "[i] Found $count_SSL3 services with SSLv3 enabled" >> $logfile
#fi
#if [[ $count_TLS10 -gt 0 ]]; then
#	echo -e "${GREEN}[i] ${WHITE}Found ${RED}$count_TLS10 services with TLSv1.0 enabled"
#	echo "[i] Found $count_TLS10 services with TLSv1.0 enabled" >> $logfile
#fi
#if [[ $count_TLS11 -gt 0 ]]; then
#	echo -e "${GREEN}[i] ${WHITE}Found ${RED}$count_TLS11 services with TLSv1.1 enabled"
#	echo "[i] Found $count_TLS11 services with TLSv1.1 enabled" >> $logfile
#fi
#if [[ $count_TLS12 -gt 0 ]]; then
#	echo -e "${GREEN}[i] ${WHITE}Found ${GREEN}$count_TLS12 services with TLSv1.2 enabled"
#	echo "[i] Found $count_TLS12 services with TLSv1.2 enabled" >> $logfile
#fi
#if [[ $count_TLS13 -gt 0 ]]; then
#	echo -e "${GREEN}[i] ${WHITE}Found ${GREEN}$count_TLS13 services with TLSv1.3 enabled"
#	echo -e "[i] Found $count_TLS13 services with TLSv1.3 enabled" >> $logfile
#fi

echo -e -n "${NC}"
