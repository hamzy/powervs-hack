#!/usr/bin/env bash

declare -a ENV_VARS
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

set -xeuo pipefail

USE_POWERVS_HACK2=true
USE_POWERVS_HACK3=false

if ${USE_POWERVS_HACK2}
then
	hash destroy-cluster2
elif ${USE_POWERVS_HACK3}
then
	hash destroy-cluster3
else
	hash openshift-install
fi

SAVE_DIR=$(mktemp --directory)
trap "/bin/rm -rf ${SAVE_DIR}" EXIT

export BASEDOMAIN="ocp-dev-ppc64le.com"
export CIS_INSTANCE="pvs-ipi-dns"
export RESOURCE_GROUP_ID="ba5e48e53192476092e188e0e0c6eb9e"

# for SERVICE_INSTANCE in "ocp-ipi-ci-mon01" "ocp-ipi-ci-osa21" "ocp-ipi-ci-sao01" "ocp-ipi-ci-syd04" "ocp-ipi-ci-syd05" "ocp-ipi-ci-tok04" "ocp-ipi-ci-tor01"
for SERVICE_INSTANCE in "ocp-ipi-ci-mon01" "ocp-ipi-ci-osa21" "ocp-ipi-ci-syd04" "ocp-ipi-ci-syd05" "ocp-ipi-ci-tok04" "ocp-ipi-ci-tor01"
do

	case ${SERVICE_INSTANCE} in
#		# DO NOT USE: Development zone
#		"ocp-ipi-ci-lon04")
#			export POWERVS_REGION="eu-gb"
#	       		export POWERVS_ZONE="lon04"
#			;;
#		# DO NOT USE: Prow cluster
#		"ocp-ipi-ci-lon06")
#			export POWERVS_REGION="eu-gb"
#	       		export POWERVS_ZONE="lon06"
#			;;
		"ocp-ipi-ci-mon01")
			export POWERVS_REGION="ca-tor"
			export POWERVS_ZONE="mon01"
			;;
		"ocp-ipi-ci-osa21")
			export POWERVS_REGION="jp-osa"
			export POWERVS_ZONE="osa21"
			;;
		"ocp-ipi-ci-sao01")
			export POWERVS_REGION="br-sao"
			export POWERVS_ZONE="sao01"
			;;
		"ocp-ipi-ci-syd04")
			export POWERVS_REGION="au-syd"
			export POWERVS_ZONE="syd04"
			;;
		"ocp-ipi-ci-syd05")
			export POWERVS_REGION="au-syd"
			export POWERVS_ZONE="syd05"
			;;
		"ocp-ipi-ci-tok04")
			export POWERVS_REGION="jp-tok"
			export POWERVS_ZONE="tok04"
			;;
		"ocp-ipi-ci-tor01")
			export POWERVS_REGION="ca-tor"
			export POWERVS_ZONE="tor01"
			;;
		*)
			echo "Error: Unknown SERVICE_INSTANCE (${SERVICE_INSTANCE})!"
			exit 1
			;;
	esac

	export CLUSTER_NAME="rdr-maocp-${POWERVS_ZONE}"
	#export CLUSTER_NAME="rdr-multiarch-${POWERVS_ZONE}"

	ibmcloud logout
	ibmcloud login --apikey "${IBMCLOUD_API_KEY}" -r "${POWERVS_REGION}"
	SERVICE_INSTANCE_CRN=$(ibmcloud resource service-instance ${SERVICE_INSTANCE} --output json | jq -r '.[].crn')
	ibmcloud pi service-target ${SERVICE_INSTANCE_CRN}

	export CIS_INSTANCE_CRN=$(ibmcloud cis instances --output json | jq -r '.[] | select (.name|test("'${CIS_INSTANCE}'")) | .crn')
	export SERVICE_INSTANCE_GUID=$(ibmcloud resource service-instance ${SERVICE_INSTANCE} --output json | jq -r '.[].guid')

	export DNS_INSTANCE_CRN=""

	for ((I=1; I <= 3; I++))
	do

		if ${USE_POWERVS_HACK2}
		then
			USE_POWERVS_HACK=true
			CMD=destroy-cluster2
			INSTANCE_CRN="-CISInstanceCRN ${CIS_INSTANCE_CRN}"
		elif ${USE_POWERVS_HACK3}
		then
			USE_POWERVS_HACK=true
			CMD=destroy-cluster3
			INSTANCE_CRN="-CISInstanceCRN ${CIS_INSTANCE_CRN} -DNSInstanceCRN ${DNS_INSTANCE_CRN}"
		fi

		if ${USE_POWERVS_HACK}
		then

			set +e
			${CMD} \
				-apiKey "${IBMCLOUD_API_KEY}" \
				-baseDomain "ocp-dev-ppc64le.com" \
				-clusterName "${CLUSTER_NAME}" \
				-infraID "${CLUSTER_NAME}" \
				${INSTANCE_CRN} \
				-region "${POWERVS_REGION}" \
				-zone "${POWERVS_ZONE}" \
				-serviceInstanceGUID "${SERVICE_INSTANCE_GUID}" \
				-resourceGroupID "${RESOURCE_GROUP_ID}" \
				-shouldDebug true \
				-shouldDelete true \
				-shouldDeleteDHCP false
			RC=$?
			set -e

		else

			cat << ___EOF___ > ${SAVE_DIR}/metadata.json
{"clusterName":"${CLUSTER_NAME}","clusterID":"","infraID":"${CLUSTER_NAME}","powervs":{"BaseDomain":"${BASEDOMAIN}","cisInstanceCRN":"${CIS_INSTANCE_CRN}","dnsInstanceCRN": "${DNS_INSTANCE_CRN}", "powerVSResourceGroup":"${RESOURCE_GROUP_ID}","region":"${POWERVS_REGION}","vpcRegion":"","zone":"${POWERVS_ZONE}","serviceInstanceID":"${SERVICE_INSTANCE_GUID}"}}
___EOF___

			set +e
			openshift-install --dir=${SAVE_DIR} destroy cluster --log-level=debug
			RC=$?
			set -e

		fi

		if [ ${RC} -eq 0 ]
		then
			break
		fi

		sleep 1m

	done
done
