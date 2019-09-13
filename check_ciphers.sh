#!/bin/bash 
#
#check_ciphers.sh check which ciphers are accepted on target hosts
#
#Version 0.1
#
#Copyright (c) 2016 Jelle Derksen jelle@epsilix.nl
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.
#
#Check which ciphers are accepted on the target hosts
#
#Script variables
me="${0##*/}"
dn='/dev/null'
hostname="${HOSTNAME}"
#The regex fqdn_port_regex will match the format www.example:443
fqdn_port_regex='^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9]):[0-9]{1,5}$'
#The regex ip_port_regex will match the format 127.0.0.1:443
ip_port_regex='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):[0-9]{1,5}$'
#Get ciphers from OpenSSL and store them colon separated in the ciphers array
IFS=':' ciphers=( $(openssl ciphers 'ALL') )
#Set colors for pretty output
red='\033[0;31m'
green='\e[0;32m'
no_color='\033[0m'

#functions
#function: usage
#description: echo usage message to stdout
#parameter: void
#example: usage
#return: 0
usage() {
	echo "usage: ${me} [ -h ] [ -t  www.example.com:port ]
	-h: show this usage message
	-t: set target hosts:port multiple usage of argument are possible"
	return 0
}

#function: err_exit
#description: display message on stderr and exit script immediately
#parameter: "$1" message to print on stderr
#example: err_exit "error message"
#return: 1
err_exit() {
	echo "${me}: ${1}" >&2
	exit 1
}

#function: check_fqdn_ip
#description: check if string is a valid fqdn or IP-address with a trailing port number
#parameter: "$1" fqdn or IP-address and port number
#example: check_fqdn_ip 127.0.0.1:443
#example: check_fqdn_ip www.example.com:443
#return: 0 on success and 1 on failure
check_fqdn_ip() {
	if [[ ${1} =~ ${fqdn_port_regex} || ${1} =~ ${ip_port_regex} ]]; then
		return 0
	else
		return 1
	fi
}

#function: check_ciper
#description: check if a given cipher is accepted on a IP-address or fqdn
#parameter: "$1" name of cipher from OpenSSL cipher suite
#parameter: "$2" IP-adress:port or fqdn:port
#example: check_ciper DHE-DSS-AES256-SHA256 www.example.com:443
#example: check_cipher DHE-DSS-AES256-SHA256 127.0.0.1:443
#return: 0 on success and >= 1 on failure
check_cipher() {
	#Test given cipher on host and save stdout and stderr in ${x}. If OpenSSL
	#returns success, we return success to the caller. Otherwise we try to
	#determine the cause for the error by examining the string in ${x} and
	#return accordingly.
	if x="$(openssl s_client -cipher "${1}" -connect "${2}" <"${dn}" 2>&1)"; then
		return 0
	#OpenSSL exit code non-zero but the connection with the given
	#cipher is established so we return 0
	elif [[ ${x} =~ '-----BEGIN CERTIFICATE-----' ]]; then
		return 0
	#Connection time out (continue with the next host)
	elif [[ ${x} =~ 'socket: Bad file descriptor' ]]; then
		return 10
	#No SSL plain text connection (continue with the next host)
	elif [[ ${x} =~ 'unknown protocol' ]]; then
		return 11
	else
		#OpenSSL cipher failed no connection established
		return 1
	fi
}

#function: check_hosts
#description: For all hosts in the check_hosts array check all the ciphers
#	      in the ciphers array. If a cipher is accepted echo ok in green
#	      otherwise echo failed in red. If the connection to a host
#	      fails, continue with the next host in the array.
#parameter: void
#example: check_hosts
#return: 0
check_hosts() {
	for host in "${check_hosts[@]}"; do
		#We print the host as the first field so we know the
		#hostname or IP-address the results belong to
		echo -en "${host},"
		count='1'
		for cipher in "${ciphers[@]}"; do
			if check_cipher "${cipher}" "${host}"; then
				echo -en "${green}${cipher}:ok${no_color}"
			elif [[ $? -ge 10 ]]; then
				echo "${me}: failed for host ${host}"
				#This host failed continue with the next
				continue 2
			else
				echo -en "${red}${cipher}:failed${no_color}"
			fi
			#We supply a newline when all the ciphers
			#are tested otherwise we supply a comma
			if [[ ${count} -eq ${#ciphers[@]} ]]; then
				echo -ne '\n'
			else
				echo -ne ','
				((count++))
			fi
		done
	done
	return 0
}

#function: get_pars
#description: Get all the parameters from the command-line
#parameter: "$@" given by the user
#example: get_pars "${@}"
#return: 0 on success and 1 on failure
get_pars() {
	if [[ -z ${1} ]]; then
		usage
		return 1
	else
		while getopts t:h n
		do
			case "${n}" in
			t)
				#Add the host in ${OPTARG} to the check_hosts array
				check_hosts+=("${OPTARG}")
				;;
			h)
				usage
				return 1
				;;
			*)
				usage
				return 1
			esac
		done
	fi
	return 0
}

#main
main() {
	if ! get_pars "${@}"; then
		err_exit 'failed to get parameters'
	fi
	#Check if the supplied hosts are valid
	for host in "${check_hosts[@]}"; do
		if ! check_fqdn_ip "${host}"; then
			err_exit "invalid host:port or ip:port ${host}"
		fi
	done
	check_hosts
}

main "${@}"
