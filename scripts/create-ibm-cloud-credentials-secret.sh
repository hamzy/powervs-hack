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

function create_ibm_cloud_credentials_secret()
{
	#log_to_file /tmp/create-ibm-cloud-credentials-secret.log
	RC=1
	while [ ${RC} -gt 0 ]
	do
		sleep 1m
		set +e
		oc --request-timeout=10s get secret/cloud-credentials -n openshift-ingress-operator > /dev/null
		RC=$?
		set -e
		echo "RC=${RC}"
	done
	oc get secret/cloud-credentials -n openshift-ingress-operator -o json \
		| sed	-e 's,"cloud-credentials","ibm-cloud-credentials",' \
			-e 's,"openshift-ingress-operator","openshift-cloud-controller-manager",' \
		| oc create -f -
	echo "create_ibm_cloud_credentials_secret: FINISHED!"
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

create_ibm_cloud_credentials_secret
