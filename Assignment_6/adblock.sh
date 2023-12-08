#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
domainNames2="domainNames2.txt"
IPAddressesSame="IPAddressesSame.txt"
IPAddressesDifferent="IPAddressesDifferent.txt"
adblockRules="adblockRules"
# adding shortcut for iptables
ip_tables="/sbin/iptables"
domainNamesSame="DomainNamesSame.txt"
domainNamesDifferent="DomainNamesDifferent.txt"

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then
        # Find different and same domains in ‘domainNames.txt’ and ‘domainsNames2.txt’ files 
	# and write them in “IPAddressesDifferent.txt and IPAddressesSame.txt" respectively
        # Write your code here...
        # get the different ip adresses and store them to IPAddressesDifferent
        fgrep -v -f $domainNames $domainNames2 > $domainNamesDifferent
        # get ip addresses from domain names
        while IFS= read -r line; do
            echo | dig +short $line | grep '^[.0-9]*$' >> $IPAddressesDifferent
        done < "$domainNamesDifferent"
        # get the ones that are the same
        fgrep -f $domainNames $domainNames2 > $domainNamesSame
        # get ip addresses from domain names
        while IFS= read -r line; do
            echo | dig +short $line | grep '^[.0-9]*$' >> $IPAddressesSame
        done < "$domainNamesSame"
        true
            
    elif [ "$1" = "-ipssame"  ]; then
        # Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.
        # Write your code here...
        while IFS= read -r line; do
        "$ip_tables" -I INPUT -s $line -j DROP
        done < "$IPAddressesSame"
        true
    elif [ "$1" = "-ipsdiff"  ]; then
        # Configure the REJECT adblock rule based on the IP addresses of $IPAddressesDifferent file.
        # Write your code here...
        while IFS= read -r line; do
            "$ip_tables" -I INPUT -s $line -j REJECT
        done < "$IPAddressesDifferent"
        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file.
        # Write your code here...
        "$ip_tables"-save > $adblockRules
        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
        # Write your code here...
        "$ip_tables"-restore < $adblockRules
        true

        
    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).
        # Write your code here...
        
        # Delete all rules in  chain or all chains
	    "$ip_tables" -F 
        true

        
    elif [ "$1" = "-list"  ]; then
        # List current rules.
        # Write your code here...
        "$ip_tables" -L 
        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ipssame\t\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.\n"
	printf "  -ipsdiff\t\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesDifferent file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0
