#!/usr/bin/env bash

function log_to_file()
{
	local LOG_FILE=$1

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
		ibmcloud login --apikey "${IBMCLOUD_API_KEY}"
		ibmcloud target -r eu-gb
	fi
}

function fix_load_balancer_hostname()
{	
	#log_to_file /tmp/fix-load-balancer-hostname.log

	CLUSTER_ID=$(jq -r '.infraID' /home/OpenShift/git/hamzyorg-installer/ocp-test/metadata.json)
	HOSTNAME_EXTERNAL="apps.rdr-hamzy-test.scnl-ibm.com"

	FOUND=false
	FILE=$(mktemp)

	while ! ${FOUND}
	do
		sleep 1m
		ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("^kube-'${CLUSTER_ID}'"))' > ${FILE}
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
	done

	HOSTNAME_LB=$(ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("^kube-'${CLUSTER_ID}'")) | .hostname')
	ID_DOMAIN=$(ibmcloud cis domains --output json | jq -r '.[] | select (.name|test("^scnl-ibm.com$")) | .id')
	ID_HOSTNAME=$(ibmcloud cis dns-records ${ID_DOMAIN} --output json | jq -r '.[] | select (.name|test("'${HOSTNAME_EXTERNAL}'$")) | .id')
	ibmcloud cis dns-record-update ${ID_DOMAIN} ${ID_HOSTNAME} --json '{ "name": "*.'${HOSTNAME}'", "type": "CNAME", "content": "'${HOSTNAME_LB}'" }'
	/bin/rm ${FILE}
	echo "fix_load_balancer_hostname: FINISHED!"
}

declare -a ENV_VARS
#ENV_VARS=( "IBMCLOUD_API_KEY" "IBMCLOUD_API2_KEY" "IBMCLOUD_API3_KEY" )
ENV_VARS=( "IBMCLOUD_API_KEY" )

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

export PATH=${PATH}:$(pwd)/bin
export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="quay.io/psundara/openshift-release:4.10-powervs"
export IBMID="hamzy@us.ibm.com"
export IBMCLOUD_REGION="lon"
export IBMCLOUD_ZONE="lon04"
export VPCREGION="eu-gb"
export BASE64_API_KEY=$(echo -n ${IBMCLOUD_API_KEY} | base64)
export KUBECONFIG=/home/OpenShift/git/hamzyorg-installer/ocp-test/auth/kubeconfig

set -x

init_ibmcloud

fix_load_balancer_hostname
