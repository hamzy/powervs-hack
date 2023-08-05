#!/usr/bin/env bash

#
# Usage example:
#

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

declare -a ENV_VARS
ENV_VARS=( "CLUSTER_DIR" "IBMCLOUD_API_KEY" )

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

if ! hash ibmcloud 1>/dev/null 2>&1
then
	echo "Error: Missing ibmcloud program!"
	exit 1
fi
for PLUGIN in tg; do
	if ! ibmcloud ${PLUGIN} > /dev/null 2>&1; then
		echo "Error: ibmcloud's ${PLUGIN} plugin is not installed?"
		ls -la ${HOME}/.bluemix/
		ls -la ${HOME}/.bluemix/plugins/
		exit 1
	fi
done
set -x
if [ ! -f "${CLUSTER_DIR}/metadata.json" ]
then
	echo "Error: missing ${CLUSTER_DIR}/metadata.json"
	exit 1
fi

CLUSTER_NAME=$(jq -r '.infraID' "${CLUSTER_DIR}/metadata.json")
echo "CLUSTER_NAME=${CLUSTER_NAME}"
if [ -z "${CLUSTER_NAME}" ]
then
	echo "Error: Cluster name is empty?"
	exit 1
fi

VPC_CRN=$(ibmcloud is vpcs --output json | jq -r '.[] | select (.name|test("'${CLUSTER_NAME}'")) | .crn')
echo "VPC_CRN=${VPC_CRN}"
if [ -z "${VPC_CRN}" ]
then
	echo "Error: VPC_CRN is empty?"
	exit 1
fi

PVS_CRN=$(ibmcloud resource service-instance hamzy-psvs-dal10 --output json | jq -r '.[].crn')
echo "PVS_CRN=${PVS_CRN}"
if [ -z "${PVS_CRN}" ]
then
	echo "Error: PVS_CRN is empty?"
	exit 1
fi

TG_ID=$(ibmcloud tg gateways --output json | jq -r '.[] | select(.name|test("'${tg-${CLUSTER_NAME}}'")) | .id')
if [ -z "${TG_ID}" ]
then
	ibmcloud tg gateway-create --name tg-${CLUSTER_NAME} --location us-south --resource-group-id c1cb9b2679344ee9951ab8b4bc22eca0
fi

TG_ID=$(ibmcloud tg gateways --output JSON | jq -r '.[] | select (.name|test("tg-'${CLUSTER_NAME}'")) | .id')
echo "TG_ID=${TG_ID}"
if [ -z "${TG_ID}" ]
then
	echo "Error: TG_ID is empty?"
	exit 1
fi

STATUS=$(ibmcloud tg gateways --output JSON | jq -r '.[] | select (.name|test("tg-'${CLUSTER_NAME}'")) | .status')
while [ "${STATUS}" != "available" ]
do
	sleep 15s
	STATUS=$(ibmcloud tg gateways --output JSON | jq -r '.[] | select (.name|test("tg-'${CLUSTER_NAME}'")) | .status')
done

TG_CONN_VPC_ID=$(ibmcloud tg connections ${TG_ID} --output json | jq -r '.[] | select (.name|test("tg-'${CLUSTER_NAME}'-conn-vpc")) | .id')
if [ -z "${TG_CONN_VPC_ID}" ]
then
	ibmcloud tg connection-create ${TG_ID} --name tg-${CLUSTER_NAME}-conn-vpc --network-type vpc --network-id "${VPC_CRN}"
fi

TG_CONN_PVS_ID=$(ibmcloud tg connections ${TG_ID} --output json | jq -r '.[] | select (.name|test("tg-'${CLUSTER_NAME}'-conn-pvs")) | .id')
if [ -z "${TG_CONN_PVS_ID}" ]
then
	ibmcloud tg connection-create ${TG_ID} --name tg-${CLUSTER_NAME}-conn-pvs --network-type power_virtual_server --network-id "${PVS_CRN}"
fi
