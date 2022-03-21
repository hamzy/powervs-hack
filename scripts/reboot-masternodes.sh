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

function reboot_master_nodes()
{	
	#log_to_file /tmp/reboot-master-nodes.log

	CLUSTER_ID=$(jq -r '.infraID' /home/OpenShift/git/hamzyorg-installer/ocp-test/metadata.json)

	FOUND=false
	FILE=$(mktemp)

	while ! ${FOUND}
	do
		ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("^'${CLUSTER_ID}'-loadbalancer$"))' > ${FILE}
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
		else
			sleep 1m
		fi
	done

	LB_ID=$(ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("^'${CLUSTER_ID}'-loadbalancer$")) | .id')

	READY=false

	while ! ${READY}
	do
		STATUS=$(ibmcloud is load-balancers --json | jq -r '.[] | select (.id|test("'${LB_ID}'")) | .operating_status')
		if [ "${STATUS}" == "online" ]
		then
			READY=true
		fi
	done

	SELECT="${CLUSTER_ID}-master"
	W_FILE=$(mktemp)
	
	while true
	do
		ibmcloud pi ins --json | jq '.Payload.pvmInstances[] | select (.serverName|test("'${SELECT}'"))' > ${W_FILE}
	
		MASTER0=$(jq -r '. | select(.serverName|test("master-0")) | .addresses[].ip' ${W_FILE})
		MASTER1=$(jq -r '. | select(.serverName|test("master-1")) | .addresses[].ip' ${W_FILE})
		MASTER2=$(jq -r '. | select(.serverName|test("master-2")) | .addresses[].ip' ${W_FILE})

		if [ -n "${MASTER0}" ] && [ -n "${MASTER1}" ] && [ -n "${MASTER2}" ]
		then
			break
		fi

		sleep 1m
	done

	OUTPUT0=$(ssh cloud-user@161.156.204.62 ssh-keyscan ${MASTER0} || true)
	OUTPUT1=$(ssh cloud-user@161.156.204.62 ssh-keyscan ${MASTER1} || true)
	OUTPUT2=$(ssh cloud-user@161.156.204.62 ssh-keyscan ${MASTER2} || true)

	if [ -z "${OUTPUT0}" ]
	then
		echo ibmcloud pi instance-hard-reboot "${CLUSTER_ID}-master-0"
	fi

	if [ -z "${OUTPUT1}" ]
	then
		echo ibmcloud pi instance-hard-reboot "${CLUSTER_ID}-master-1"
	fi

	if [ -z "${OUTPUT2}" ]
	then
		echo ibmcloud pi instance-hard-reboot "${CLUSTER_ID}-master-2"
	fi

	/bin/rm ${FILE} ${W_FILE}
	echo "reboot_master_nodes: FINISHED!"
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

reboot_master_nodes
