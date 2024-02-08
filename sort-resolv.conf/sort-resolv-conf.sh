#!/usr/bin/env bash

set -euo pipefail

function sort_nameservers {
	echo "sort_nameservers"
	IFS=$'\n' NAMESERVERS=( $(sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n <<<"${NAMESERVERS[*]}") )
	IFS=$'\n' NAMESERVERS10=( $(sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n <<<"${NAMESERVERS10[*]}") )
	unset IFS
}

RESOLV_CONF=/etc/resolv.conf

echo "Num args: $#"
if (( $# == 1 ))
then
	RESOLV_CONF=$1
fi
echo "RESOLV_CONF=${RESOLV_CONF}"

FILE=$(mktemp)

trap "/bin/rm -rf ${FILE}" EXIT

BEFORE_NS=true

declare -a LINES_BEFORE_NS=()
declare -a LINES_AFTER_NS=()
declare -a NAMESERVERS=()
declare -a NAMESERVERS10=()

echo "============ BEGIN: Old resolv.conf ============"
while read LINE
do
	if [[ "${LINE}" == nameserver* ]]
	then
		BEFORE_NS=false
		FOUND_NS=true
		NAMESERVER=$(echo "${LINE}" | cut -f2 -d' ')
		if [[ ${NAMESERVER} == 10.* ]]
		then
			NAMESERVERS10+=( ${NAMESERVER} )
		else
			NAMESERVERS+=( ${NAMESERVER} )
		fi
	else
		FOUND_NS=false
	fi

	if ${BEFORE_NS}
	then
		LINES_BEFORE_NS+=( "${LINE}" )
	else
		if ! ${FOUND_NS}
		then
			LINES_AFTER_NS+=( "${LINE}" )
		fi
	fi

	echo ${LINE}
done < ${RESOLV_CONF}
echo "============ END: Old resolv.conf ============"

echo "LINES_BEFORE_NS: ${#LINES_BEFORE_NS[@]}"
for ((i = 0; i < ${#LINES_BEFORE_NS[@]}; i++))
do
    echo "${LINES_BEFORE_NS[$i]}"
done

echo "NAMESERVERS: ${#NAMESERVERS[@]}"
for ((i = 0; i < ${#NAMESERVERS[@]}; i++))
do
    echo "${NAMESERVERS[$i]}"
done

echo "NAMESERVERS10: ${#NAMESERVERS10[@]}"
for ((i = 0; i < ${#NAMESERVERS10[@]}; i++))
do
    echo "${NAMESERVERS10[$i]}"
done

sort_nameservers

echo "NAMESERVERS: ${#NAMESERVERS[@]}"
for ((i = 0; i < ${#NAMESERVERS[@]}; i++))
do
    echo "${NAMESERVERS[$i]}"
done

echo "NAMESERVERS10: ${#NAMESERVERS10[@]}"
for ((i = 0; i < ${#NAMESERVERS10[@]}; i++))
do
    echo "${NAMESERVERS10[$i]}"
done

echo "LINES_AFTER_NS: ${#LINES_AFTER_NS[@]}"
for ((i = 0; i < ${#LINES_AFTER_NS[@]}; i++))
do
    echo "${LINES_AFTER_NS[$i]}"
done

(
	for ((i = 0; i < ${#LINES_BEFORE_NS[@]}; i++))
	do
    		echo "${LINES_BEFORE_NS[$i]}"
	done
	for ((i = 0; i < ${#NAMESERVERS10[@]}; i++))
	do
    		echo "nameserver ${NAMESERVERS10[$i]}"
	done
	for ((i = 0; i < ${#NAMESERVERS[@]}; i++))
	do
    		echo "nameserver ${NAMESERVERS[$i]}"
	done
	for ((i = 0; i < ${#LINES_AFTER_NS[@]}; i++))
	do
    		echo "${LINES_AFTER_NS[$i]}"
	done
) > /etc/resolv.conf

echo "============ BEGIN: New resolv.conf ============"
/bin/cp /etc/resolv.conf /etc/resolv.conf.orig
cat /etc/resolv.conf
echo "============ END: New resolv.conf ============"
