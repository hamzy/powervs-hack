#!/usr/bin/env bash

function log_to_file()
{
	local LOG_FILE=$1

	/bin/rm -f ${LOG_FILE}
	# Close STDOUT file descriptor
	exec 1<&-
	# Close STDERR FD
	exec 2<&-
	# Open STDOUT as $LOG_FILE file for read and write.
	exec 1<>${LOG_FILE}
	# Redirect STDERR to STDOUT
	exec 2>&1
}

function init_ibmcloud()
{
	if ! ibmcloud iam oauth-tokens 1>/dev/null 2>&1
	then
		ibmcloud login --apikey "${IBMCLOUD_API_KEY}" -r ${VPCREGION}
	fi
}

function delete_wildcard_dns()
{	
	#log_to_file /tmp/delete-wildcard-dns.log

	HOSTNAME_WILDCARD="apps.rdr-hamzy-test.scnl-ibm.com"
	ID_DOMAIN=$(ibmcloud cis domains --output json | jq -r '.[] | select (.name|test("^scnl-ibm.com$")) | .id')

	FOUND=false
	FILE=$(mktemp)

	while ! ${FOUND}
	do
		sleep 1m

		ibmcloud cis dns-records ${ID_DOMAIN} --output json > ${FILE}
		RC=$?
		if [ ${RC} -gt 0 ]
		then
			continue
		fi

		ibmcloud cis dns-records ${ID_DOMAIN} --output json | jq -r '.[] | select (.name|test("'${HOSTNAME_WILDCARD}'$"))' > ${FILE}
		RC=$?
		if [ ${RC} -eq 0 ]
		then
			LINE_OUTPUT=$(wc -l ${FILE})
			RC=$?
			if [ ${RC} -eq 0 ]
			then
				LINES=$(echo "${LINE_OUTPUT}" | cut -f1 -d' ')
				RC=$?
				if (( ${LINES} > 0 ))
				then
					FOUND=true
				fi
			fi
		fi

		if ${FOUND}
		then
			ID_WILDCARD=$(jq -r --slurp '.[0].id' ${FILE})
			ibmcloud cis dns-record-delete ${ID_DOMAIN} ${ID_WILDCARD}
		fi
	done

	/bin/rm ${FILE}
	echo "delete_wildcard_dns: FINISHED!"
}

declare -a ENV_VARS
ENV_VARS=( "IBMCLOUD_API_KEY" "CLUSTER_DIR" "IBMID" "CLUSTER_NAME" "IBMCLOUD_REGION" "IBMCLOUD_ZONE" "VPCREGION" )
#ENV_VARS+=( "IBMCLOUD_API2_KEY" "IBMCLOUD_API3_KEY" )

for VAR in ${ENV_VARS[@]}
do
	if [[ ! -v ${VAR} ]]
	then
		echo "${VAR} must be set!"
		exit 1
	fi
	VALUE=$(eval "echo \"\${${VAR}}\"")
	if [[ -z "${VALUE}" ]]
	then
		echo "${VAR} must be set!"
		exit 1
	fi
done

set -euo pipefail

export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="quay.io/psundara/openshift-release:4.10-powervs"

export PATH=${PATH}:$(pwd)/bin
export BASE64_API_KEY=$(echo -n ${IBMCLOUD_API_KEY} | base64)
export KUBECONFIG=${CLUSTER_DIR}/auth/kubeconfig
export IC_API_KEY=${IBMCLOUD_API_KEY}

set -x

init_ibmcloud

delete_wildcard_dns
