#!/usr/bin/env bash
set -xe

if [ -z "${IBMCLOUD_API_KEY}" ]
then
	echo "Error: environment variable IBMCLOUD_API_KEY is not set!"
	exit 1
fi

DHCP_ID=$1

if [ -z "${POWERVS_REGION}" ]
then
	POWERVS_REGION="lon"
fi
if [ -z "${SERVICE_INSTANCE}" ]
then
	SERVICE_INSTANCE="powervs-ipi-lon04"
fi

SERVICE_ID=$(ibmcloud pi service-list --json | jq -r '.[] | select (.Name|test("'${SERVICE_INSTANCE}'")) | .CRN')
[ -z "${SERVICE_INSTANCE}" ] && exit 1

CLOUD_INSTANCE_ID=$(echo ${SERVICE_ID} | cut -d: -f8)
[ -z "${CLOUD_INSTANCE_ID}" ] && exit 1

BEARER_TOKEN=$(curl --silent -X POST "https://iam.cloud.ibm.com/identity/token" -H "content-type: application/x-www-form-urlencoded" -H "accept: application/json" -d "grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey&apikey=${IBMCLOUD_API_KEY}" | jq -r .access_token)
[ -z "${BEARER_TOKEN}" -o "${BEARER_TOKEN}" == "null" ] && exit 1

if [ -z "${DHCP_ID}" ]
then

	curl -s --location --request GET "https://${POWERVS_REGION}.power-iaas.cloud.ibm.com/pcloud/v1/cloud-instances/${CLOUD_INSTANCE_ID}/services/dhcp" --header 'Content-Type: application/json' --header "CRN: ${SERVICE_ID}" --header "Authorization: Bearer ${BEARER_TOKEN}" | jq -r '.[] | "\(.id) - \(.network.name)"'

else

	ACTION=GET
	test "$2" == "-d" && ACTION=DELETE

	curl -s --location --request ${ACTION} "https://${POWERVS_REGION}.power-iaas.cloud.ibm.com/pcloud/v1/cloud-instances/${CLOUD_INSTANCE_ID}/services/dhcp/${DHCP_ID}" --header 'Content-Type: application/json' --header "CRN: ${SERVICE_ID}" --header "Authorization: Bearer ${BEARER_TOKEN}" | jq -r '.'

fi
