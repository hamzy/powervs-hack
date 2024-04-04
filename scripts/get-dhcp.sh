#!/usr/bin/env bash
set -u
#set -euo pipefail

if [ -z "${IBMCLOUD_API_KEY}" ]
then
	echo "Error: environment variable IBMCLOUD_API_KEY is not set!"
	exit 1
fi

DHCP_ID=${1-}

if [ -z "${POWERVS_REGION}" ]
then
	POWERVS_REGION="lon"
fi
if [ -z "${SERVICE_INSTANCE}" ]
then
	SERVICE_INSTANCE="powervs-ipi-lon04"
fi

DNSRESOLV=""
hash getent && DNSRESOLV="getent ahostsv4"
hash dig && DNSRESOLV="dig +short"
if [ -z "${DNSRESOLV}" ]
then
	echo "Either getent or dig must be present!"
	exit 1
fi

if [ -z "$(${DNSRESOLV} ${POWERVS_REGION}.power-iaas.cloud.ibm.com)" ]
then
	echo "Error: POWERVS_REGION (${POWERVS_REGION}) is invalid!"
	exit 1
fi

[ -z "${SERVICE_INSTANCE}" ] && exit 1
SERVICE_ID=$(ibmcloud pi workspace list --json | jq -r '.Payload.workspaces[] | select (.name|test("^'${SERVICE_INSTANCE}'$")) | .details.crn')
if [ -z "${SERVICE_ID}" ]
then
	echo "Error: ${SERVICE_INSTANCE} does not exist!"
	exit 1
fi
echo "SERVICE_ID=${SERVICE_ID}"

CLOUD_INSTANCE_ID=$(echo ${SERVICE_ID} | cut -d: -f8)
[ -z "${CLOUD_INSTANCE_ID}" ] && exit 1
echo "CLOUD_INSTANCE_ID=${CLOUD_INSTANCE_ID}"

echo "DATE=$(TZ=UTC date -R)"

BEARER_TOKEN=$(curl --silent -X POST "https://iam.cloud.ibm.com/identity/token" -H "content-type: application/x-www-form-urlencoded" -H "accept: application/json" -d "grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey&apikey=${IBMCLOUD_API_KEY}" | jq -r .access_token)
[ -z "${BEARER_TOKEN}" ] && exit 1
[ "${BEARER_TOKEN}" == "null" ] && exit 1

if [ -z "${DHCP_ID}" ]
then

	RESULT=$(curl --silent --location --request GET "https://${POWERVS_REGION}.power-iaas.cloud.ibm.com/pcloud/v1/cloud-instances/${CLOUD_INSTANCE_ID}/services/dhcp" --header 'Content-Type: application/json' --header "CRN: ${SERVICE_ID}" --header "Authorization: Bearer ${BEARER_TOKEN}")

	if [ $(echo "${RESULT}" | jq -r 'type') == "object" ]
	then
		if [ $(echo "${RESULT}" | jq -r 'has("error")') == "true" ]
		then
			echo "${RESULT}" | jq -r '.description'
			exit 1
		fi
	fi

	echo "${RESULT}" | jq -r '.[] | "\(.id) - \(.network.name)"'
	RC=${PIPESTATUS[1]}

	if [ ${RC} -gt 0 ]
	then
		echo "${RESULT}"
		exit 1
	fi

else

	CURL_ACTION=${2-g}
	case "${CURL_ACTION}" in
		"-d"|"-D")
			ACTION=DELETE
			RESULT=$(curl --silent --location --request ${ACTION} "https://${POWERVS_REGION}.power-iaas.cloud.ibm.com/pcloud/v1/cloud-instances/${CLOUD_INSTANCE_ID}/services/dhcp/${DHCP_ID}" --header 'Content-Type: application/json' --header "CRN: ${SERVICE_ID}" --header "Authorization: Bearer ${BEARER_TOKEN}")
			;;
		"-c"|"-C")
			ACTION=POST
			CLOUD_CON_ID=${DHCP_ID}
			# NOTE: You can also add "name": "value" to the --data section
			RESULT=$(curl --silent --location --request ${ACTION} "https://${POWERVS_REGION}.power-iaas.cloud.ibm.com/pcloud/v1/cloud-instances/${CLOUD_INSTANCE_ID}/services/dhcp" --header 'Content-Type: application/json' --header "CRN: ${SERVICE_ID}" --header "Authorization: Bearer ${BEARER_TOKEN}" --data '{"cloudConnectionID": "'${CLOUD_CON_ID}'"}')
			;;
		"-q"|"-Q"|"-g"|"-G"|*)
			ACTION=GET
			RESULT=$(curl --silent --location --request ${ACTION} "https://${POWERVS_REGION}.power-iaas.cloud.ibm.com/pcloud/v1/cloud-instances/${CLOUD_INSTANCE_ID}/services/dhcp/${DHCP_ID}" --header 'Content-Type: application/json' --header "CRN: ${SERVICE_ID}" --header "Authorization: Bearer ${BEARER_TOKEN}")
			;;
	esac

	if [ $(echo "${RESULT}" | jq -r 'type') == "object" ]
	then
		if [ $(echo "${RESULT}" | jq -r 'has("error")') == "true" ]
		then
			echo "${RESULT}" | jq -r '.description'
			exit 1
		fi
	fi

	echo "${RESULT}" | jq -r '.'
	RC=${PIPESTATUS[1]}

	if [ ${RC} -gt 0 ]
	then
		echo "${RESULT}"
		exit 1
	else
		case "${CURL_ACTION}" in
			"-q"|"-Q")
				PVM_INSTANCE_ID=$(echo "${RESULT}" | jq -r '.id')
				RESULT=$(curl --silent --location --request ${ACTION} "https://${POWERVS_REGION}.power-iaas.cloud.ibm.com/pcloud/v1/cloud-instances/${CLOUD_INSTANCE_ID}/pvm-instances/${PVM_INSTANCE_ID}" --header 'Content-Type: application/json' --header "CRN: ${SERVICE_ID}" --header "Authorization: Bearer ${BEARER_TOKEN}")
				echo "${RESULT}" | jq -r '.'
				RC=${PIPESTATUS[1]}
				;;
		esac
	fi

fi
