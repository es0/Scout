#!/bin/bash

scriptStart=`date +%s`

echo -e "\e[93m    _____                 _     "
echo -e "\e[31m   /  ___|               | |    "
echo -e "\e[36m   \ \`--.  ___ ___  _   _| |_  "
echo -e "\e[32m    \`--. \/ __/ _ \| | | | __| "
echo -e "\e[93m   /\__/ / (_| (_) | |_| | |_   "
echo -e "\e[95m   \____/ \___\___/ \__,_|\__|  "
echo -e "\e[36m         Network Scanner v0.1   "                           
echo -e "\e[95m         by es07er1k            "


#ip-range='10.11.1.1/24'

ports='7,9,11,13,18,19,21-23,25,37,39,42,49,50,53,65,67-70,79-81,88,98,100,105-107,109-111,113,118,119,123,129,135,137-139,143,150,161-164,174,177-179,191,199-202,204,206,209,210,213,220,345,346,347,369-372,389,406,407,422,443-445,487,500,512-514,517,518,520,525,533,538,548,554,563,587,610-612,631-634,636,642,653,655,657,666,706,750-752,765,779,808,873,901,923,941,946,992-995,1001,1023-1030,1080,1210,1214,1234,1241,1334,1349,1352,1423-1425,1433,1434,1524,1525,1645,1646,1649,1701,1718,1719,1720,1723,1755,1812,1813,2048-2050,2101-2104,2140,2150,2233,2323,2345,2401,2430,2431,2432,2433,2583,2628,2776,2777,2988,2989,3050,3130,3150,3232,3306,3389,3456,3493,3542-3545,3632,3690,3801,4000,4400,4321,4567,4899,5002,5136-5139,5150,5151,5222,5269,5308,5354,5355,5422-5425,5432,5503,5555,5556,5678,6000-6007,6346,6347,6543,6544,6789,6838,6666-6670,7000-7009,7028,7100,7983,8079-8082,8088,8787,8879,9090,9101-9103,9325,9359,10000,10026,10027,10067,10080,10081,10167,10498,11201,15345,17001-17003,18753,20011,20012,21554,22273,26274,27374,27444,27573,31335-31338,31787,31789,31790,31791,32668,32767-32780,33390,47262,49301,54320,54321,57341,58008,58009,58666,59211,60000,60006,61000,61348,61466,61603,63485,63808,63809,64429,65000,65506,65530-65535'

# Quick scanner for finding live hosts and basic info gathering for each host and services

# Make project directory
rm -rf ~/.scout/scan-results
mkdir -p ~/.scout/scan-results

# Nmap find live hosts
echo -e "\e[32m[Action] SCANNING for alive hosts... "
nmap -sP 10.11.1.1/24 | grep "scan report for" | cut -d " " -f 5 > ~/.scout/scan-results/Alive-Hosts.txt
numHosts=$(wc -l ~/.scout/scan-results/Alive-Hosts.txt | awk '{ print $1 }')
echo -e "\e[33m[Info] Found $numHosts Live Hosts "

# For each host
#for x in `cat ~/.scout/scan-results/Alive-Hosts.txt` ;do echo -e "\e[33m[i] Scanning Host $x"; mkdir -p ~/.scout/scan-results/$x;  nmap -T4 -p- -oA  $x  > /tmp/pwk-lab/internal/scan/ssh/$x ; done


# Create folder for hosts
echo -e "\e[33m[Info] Creating folders for host "; 
for x in `cat ~/.scout/scan-results/Alive-Hosts.txt` ;do mkdir -p ~/.scout/scan-results/$x; mkdir -p ~/.scout/scan-results/$x/nmap-scans; done

# Find all the ports!!!
#echo -e "\e[32m   *********FINDING ALL TEH PORTS********"
#nmap -T4 --open -iL ~/.scout/scan-results/Alive-Hosts.txt -p 1-65535 -oA PORTS

# initial nmap tcp scan
echo -e "\e[32m   *********STARTING TCP SCANS********"
start=`date +%s`
for x in `cat ~/.scout/scan-results/Alive-Hosts.txt` ;do echo -e "\e[33m[Info] Scanning Host $x for TCP Ports"; nmap -sV -T5 -Pn -p$ports -oA ~/.scout/scan-results/$x/nmap-scans/tcp-scan $x &> /dev/null; done
end=`date +%s`

runtime=$(((end-start) / 60))

echo -e "\e[32m[!] Finished TCP scan in $runtime minutes"


# initial nmap udp scan
echo -e "\e[32m   *********STARTING UDP SCANS********" 
echo -e "\e[31m   *********IT TAKES A WHILE.. UDP SUX********" 
start=`date +%s`
for x in `cat ~/.scout/scan-results/Alive-Hosts.txt` ;do echo -e "\e[33m[Info] Scanning Host $x for UDP Ports"; nmap -sV -sU -Pn --max-retries 1 --min-parallelism 500 -T5 -p$ports -oA ~/.scout/scan-results/$x/nmap-scans/udp-scan $x &> /dev/null; done
end=`date +%s`

runtime=$(((end-start) / 60))

echo -e "\e[32m[!] Finished UDP scan in $runtime minutes"



###########################
# parse scan results 
###########################


#  Parse ports
echo -e "\e[32m   *********FINDING ALL TEH PORTS********"
find ~/.scout/scan-results/ -name *.gnmap | xargs grep -o -E "[0-9]+/open" |cut -d "/" -f7 | cut -d ":" -f2 | sort -u > ~/.scout/scan-results/open-ports.txt
portCount=$(wc -l ~/.scout/scan-results/open-ports.txt | awk '{ print $1 }')
echo -e "\e[33m[Info] Found $portCount open ports on $numHosts hosts "
echo -e "\e[33m[Info] Saving Results to file."
find ~/.scout/scan-results/ -name *-*.gnmap | xargs egrep -v "^#|Status: Up" | cut -d " " -f2,4- | sed -n -e 's/Ignored.*//p' | awk '{print "\n    Host: " $1 " Ports: " NF-1; $1=""; for(i=2; i<=NF; i++) { a=a" "$i; }; split(a,s,","); for(e in s) { split(s[e],v,"/"); printf "%-8s %s/%-7s %s\n" , v[2], v[3], v[1], v[5]}; a="" }' >> ~/.scout/scan-results/report.txt

echo -e "\e[33m[Info] Results saved to: ~/.scout/scan-results/report.txt"

# Quick parse of open ports and services per host 
echo -e "\n_______________________________________________________________________"
echo -e "\e[32m   *********Running Quick Parse********"
echo -e "\n\e[33m[Info] Running a quick parse on scan results."
find ~/.scout/scan-results/ -name *-*.gnmap | xargs egrep -v "^#|Status: Up" | cut -d " " -f2,4- | sed -n -e 's/Ignored.*//p' | awk '{print "\n    Host: " $1 " Ports: " NF-1; $1=""; for(i=2; i<=NF; i++) { a=a" "$i; }; split(a,s,","); for(e in s) { split(s[e],v,"/"); printf "%-8s %s/%-7s %s\n" , v[2], v[3], v[1], v[5]}; a="" }'


#echo -e "\n\e[33m[Info] Running a quick parse on the udp scan results."
#find ~/.scout/scan-results/ -name udp-*.gnmap | xargs egrep -v "^#|Status: Up" | cut -d " " -f2,4- | sed -n -e 's/Ignored.*//p' | awk '{print "\n    Host: " $1 " Ports: " NF-1; $1=""; for(i=2; i<=NF; i++) { a=a" "$i; }; split(a,s,","); for(e in s) { split(s[e],v,"/"); printf "%-8s %s/%-7s %s\n" , v[2], v[3], v[1], v[5]}; a="" }'

# Top Services
#echo -e "\n_______________________________________________________________________"
#echo -e "\e[32m   *********Top Services******** \e[49m "
#find ~/.scout/scan-results/ -name *.gnmap | xargs egrep -v "^#|Status: Up" | tr ',' '\n' | sed -e 's/^[ \t]*//' | awk -F '/' '{print $5}' | grep -v "^$" | sort | uniq -c | sort -k 1 -nr

###########################
# More scans for parsed services
############################

# Parsing HTTP hosts
#find ~/.scout/scan-results/ -name *.gnmap | xargs egrep -v "^#|Status: Up" | tr ',' '\n' | sed -e 's/^[ \t]*//' | awk -F '/' '{print $5}' | grep -v "^$" | sort | uniq -c | sort -k 1 -nr
# Parsing SMB hosts

scriptEnd=`date +%s`
scriptRuntime=$(((scriptEnd - scriptStart) / 60))

echo -e "\e[32m[!] Scout finished running in $scriptRuntime minutes"
