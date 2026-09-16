#!/bin/bash


check_prips() {
# check prips dependency

	service='prips'
	service_path=$(which "$service")

	if [ -z "$service_path" ]; then
		echo 'Please install prips'
		echo 'sudo apt install -y prips'
	fi
}


expand_networks() {
# return reverse CIDR notation 
	cidr_networks=("$@")
	for network in ${cidr_networks[*]}; do
		prips "$network"|sort -R
	done
}


lookup_ip() {
# given an IP, ask public recursive server to return fqdn
	ip=$1
	domain=$(host "$ip" 8.8.8.8)
	echo "$ip $domain"|
	grep -v 'not found'|
	grep 'ointer'|
	awk '{print $5}'|
	sed 's/.$//g'
}


main() {
	check_prips

	# this computers core count
	cores=$(grep -c proces /proc/cpuinfo)

	# all the IPs to check
	ip_list=$(expand_networks "${cidr_networks[*]}")

	# MULTITHREAD DNS lookups!
	echo "$ip_list"|
	xargs -P "$cores" -n 1 -I {} bash -c 'lookup_ip "$1"' _ {}
}


[ $# -eq 0 ] && { echo "Usage: $0 8.8.8.0/32 192.168.1.0/24"; exit 1; }

# array of networks in CIDR notation
cidr_networks=("$@")

# scope hack for thread safty
export -f lookup_ip

main
