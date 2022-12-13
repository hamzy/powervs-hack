#!/usr/bin/env bash

# Example:
# (export BASEDOMAIN="ocp-dev-ppc64le.com"; export CIS_INSTANCE="pvs-ipi-dns"; export IBMCLOUD_API_KEY="FILL-IN"; export NAME="rdr-maocp-syd04"; export RESOURCE_GROUP_ID="ba5e48e53192476092e188e0e0c6eb9e"; export SERVICE_INSTANCE="ocp-ipi-ci-syd04"; ./scripts/create-destroy-test.sh)
#

declare -a ENV_VARS
ENV_VARS=( "BASEDOMAIN" "CIS_INSTANCE" "IBMCLOUD_API_KEY" "NAME" "RESOURCE_GROUP_ID" "SERVICE_INSTANCE" )

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

if [ ! -f ~/.ssh/id_rsa.pub ]
then
	echo "Error: ~/.ssh/id_rsa.pub needs to exist!"
	exit 1
fi

set -xeuo pipefail

SAVE_DIR=$(mktemp --directory)
trap "/bin/rm -rf ${SAVE_DIR}" EXIT

case ${SERVICE_INSTANCE} in
#	# DO NOT USE: Development zone
#	"ocp-ipi-ci-lon04")
#		export POWERVS_REGION="eu-gb"
#		export POWERVS_ZONE="lon04"
#		;;
#	# DO NOT USE: Prow cluster
#	"ocp-ipi-ci-lon06")
#		export POWERVS_REGION="eu-gb"
#		export POWERVS_ZONE="lon06"
#		;;
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
	"powervs-ipi-syd04")
		export POWERVS_REGION="au-syd"
		export POWERVS_ZONE="syd04"
		;;
	*)
		echo "Error: Unknown SERVICE_INSTANCE (${SERVICE_INSTANCE})!"
		exit 1
		;;
esac

POWER_IAAS_HOST=$(echo "${POWERVS_ZONE}" | tr -d '[0-9]')

DNSRESOLV=""
hash getent && DNSRESOLV="getent ahostsv4"
hash dig && DNSRESOLV="dig +short"
if [ -z "${DNSRESOLV}" ]
then
	echo "Either getent or dig must be present!"
	exit 1
fi

if [ -z "$(${DNSRESOLV} ${POWER_IAAS_HOST}.power-iaas.cloud.ibm.com)" ]
then
	echo "Error: POWER_IAAS_HOST (${POWER_IAAS_HOST}) is invalid!"
	exit 1
fi

#
# {name: "Cloud Instances", execute: o.destroyCloudInstances},
# {name: "Power Instances", execute: o.destroyPowerInstances},
# {name: "Load Balancers", execute: o.destroyLoadBalancers},
# {name: "Subnets", execute: o.destroySubnets},
# {name: "Public Gateways", execute: o.destroyPublicGateways},
# {name: "DHCPs", execute: o.destroyDHCPNetworks},
#- {name: "Images", execute: o.destroyImages},
# {name: "Security Groups", execute: o.destroySecurityGroups},
# {name: "Cloud Connections", execute: o.destroyCloudConnections},
# {name: "Networks", execute: o.destroyNetworks},
# {name: "VPCs", execute: o.destroyVPCs},
#- {name: "Cloud Object Storage Instances", execute: o.destroyCOSInstances},
# {name: "DNS Records", execute: o.destroyDNSRecords},
# {name: "Cloud SSH Keys", execute: o.destroyCloudSSHKeys},
# {name: "Power SSH Keys", execute: o.destroyPowerSSHKeys},
#

ibmcloud logout
ibmcloud login --apikey "${IBMCLOUD_API_KEY}" -r "${POWERVS_REGION}"
SERVICE_INSTANCE_CRN=$(ibmcloud resource service-instance ${SERVICE_INSTANCE} --output json | jq -r '.[].crn')
ibmcloud pi service-target ${SERVICE_INSTANCE_CRN}

CIS_INSTANCE_CRN=$(ibmcloud cis instances --output json | jq -r '.[] | select (.name|test("'${CIS_INSTANCE}'")) | .crn')
SERVICE_INSTANCE_GUID=$(ibmcloud resource service-instance ${SERVICE_INSTANCE} --output json | jq -r '.[].guid')

VPC_IMAGE_NAME=$(ibmcloud is images --output json | jq -r '.[] | select (.name|test("ibm-centos.*amd64")) | select (.status|test("available")) | .name')

CENTOS_ID=$(ibmcloud pi images --json | jq -r '.images[] | select (.name|test("CentOS-Stream-8")) | .imageID')
if [ -z "${CENTOS_ID}" ]
then
	ibmcloud pi image-create CentOS-Stream-8

	CENTOS_ID=$(ibmcloud pi images --json | jq -r '.images[] | select (.name|test("CentOS-Stream-8")) | .imageID')

	STATE="queued"
	while [ "${STATE}" == "queued" ]
	do
		sleep 15s
		STATE=$(ibmcloud pi image ${CENTOS_ID} --json | jq -r '.state')
	done
fi

VPC_NAME="${NAME}-vpc"

ibmcloud is vpc-create ${VPC_NAME} --resource-group-id ${RESOURCE_GROUP_ID}

STATUS="unknown"
while [ "${STATUS}" != "available" ]
do
	STATUS=$(ibmcloud is vpc ${VPC_NAME} --output json | jq -r '.status')
done

VPC_CRN=$(ibmcloud is vpcs --output json | jq -r '.[] | select (.name|test("'${VPC_NAME}'")) | .crn')
echo "${VPC_CRN}"
VPC_ID=$(ibmcloud is vpcs --output json | jq -r '.[] | select (.name|test("'${VPC_NAME}'")) | .id')
echo "VPC_ID=${VPC_ID}"

VPC_SG_NAME="${NAME}-vpc-sg"

ibmcloud is security-group-create ${VPC_SG_NAME} ${VPC_NAME}

ZONE_NAME=$(ibmcloud is zones --output json | jq -r '.[0].name')

VPC_SUBNET_NAME="${NAME}-vpc-sn"

ibmcloud is subnet-create ${VPC_SUBNET_NAME} ${VPC_NAME} --ipv4-address-count 256 --zone ${ZONE_NAME}

VPC_SUBNET_ZONE=$(ibmcloud is subnet ${VPC_SUBNET_NAME} --output json | jq -r '.zone.name')

VPC_GATEWAY_NAME="${NAME}-gw"

ibmcloud is public-gateway-create ${VPC_GATEWAY_NAME} ${VPC_NAME} ${VPC_SUBNET_ZONE}

VPC_SSH_KEY_NAME="${NAME}-vpc-ssh"

ibmcloud is key-create ${VPC_SSH_KEY_NAME} @~/.ssh/id_rsa.pub

VPC_VM_NAME="${NAME}-vpc-vm"

ibmcloud is instance-create ${VPC_VM_NAME} ${VPC_ID} ${VPC_SUBNET_ZONE} cx2-2x4 ${VPC_SUBNET_NAME} --keys ${VPC_SSH_KEY_NAME} --image ${VPC_IMAGE_NAME} --resource-group-id ${RESOURCE_GROUP_ID}

CC_NAME="${NAME}-cc"

ibmcloud pi connection-create ${CC_NAME} --speed 1000 --vpc --vpcID ${VPC_CRN}

CC_ID=$(ibmcloud pi connection ${CC_NAME} --json | jq -r '.cloudConnectionID')

# CC_STATUS=$(ibmcloud pi connections --json | jq -r '.cloudConnections[] | select (.name|test("'${CC_NAME}'")) | .linkStatus')
# CC_STATUS=$(ibmcloud pi connection ${CC_NAME} --json | jq -r '.linkStatus')

LB_NAME="${NAME}-lb"

ibmcloud is load-balancer-create ${LB_NAME} public --subnet ${VPC_SUBNET_NAME} --vpc ${VPC_NAME} --sg ${VPC_SG_NAME} --resource-group-id ${RESOURCE_GROUP_ID}

# LB_STATUS=$(ibmcloud is load-balancer ${LB_NAME} --output json | jq -r '.operating_status')

PI_SSH_KEY_NAME="${NAME}-pi-ssh"

ibmcloud pi key-create ${PI_SSH_KEY_NAME} --key "$(cat ~/.ssh/id_rsa.pub)"

PI_NETWORK_NAME="${NAME}-pi-nw"

if ibmcloud pi network ${PI_NETWORK_NAME} > /dev/null 2>&1
then

	# Already exists
	:

else

	ibmcloud pi network-create-public ${PI_NETWORK_NAME} --dns-servers "1.1.1.1 9.9.9.9 8.8.8.8"

	for ((I=1; I<=20; I++))
	do
		if ibmcloud pi network ${PI_NETWORK_NAME} > /dev/null 2>&1
		then
			break
		fi
		sleep 15s
	done

fi

PI_NETWORK_ID=$(ibmcloud pi network ${PI_NETWORK_NAME} --json | jq -r '.networkID')

PI_VM_NAME="${NAME}-pi-vm"

ibmcloud pi instance-create ${PI_VM_NAME} --image CentOS-Stream-8 --memory 8 --key-name ${PI_SSH_KEY_NAME} --network ${PI_NETWORK_ID} --storage-type tier1

BEARER_TOKEN=$(curl --silent -X POST "https://iam.cloud.ibm.com/identity/token" -H "content-type: application/x-www-form-urlencoded" -H "accept: application/json" -d "grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey&apikey=${IBMCLOUD_API_KEY}" | jq -r .access_token)
[ -z "${BEARER_TOKEN}" ] && exit 1
[ "${BEARER_TOKEN}" == "null" ] && exit 1

CLOUD_INSTANCE_ID=$(echo ${SERVICE_INSTANCE_CRN} | cut -d: -f8)

ACTION=POST
RESULT=$(curl --silent --location --request ${ACTION} "https://${POWER_IAAS_HOST}.power-iaas.cloud.ibm.com/pcloud/v1/cloud-instances/${CLOUD_INSTANCE_ID}/services/dhcp" --header 'Content-Type: application/json' --header "CRN: ${SERVICE_INSTANCE_CRN}" --header "Authorization: Bearer ${BEARER_TOKEN}" --data '{"cloudConnectionID": "'${CC_ID}'", "name": "'${NAME}'"}')
echo "DHCP create result: ${RESULT}"

USE_DNS=true

if ${USE_DNS}
then

	ibmcloud cis instance-set $(ibmcloud cis instances --output json | jq -r '.[] | select(.name|test("'${CIS_INSTANCE}'")) | .id')

	BASENAME=$(ibmcloud cis domains --output json | jq -r '.[0].name')
	ID_DOMAIN=$(ibmcloud cis domains --output json | jq -r '.[0].id')

	ibmcloud cis dns-record-create ${ID_DOMAIN} --json '{ "name": "api.'${NAME}.${BASENAME}'", "type": "A", "content": "127.0.0.1", "ttl": 60 }'
	ibmcloud cis dns-record-create ${ID_DOMAIN} --json '{ "name": "api-int.'${NAME}.${BASENAME}'", "type": "A", "content": "127.0.0.1", "ttl": 60 }'

else

	if ! ibmcloud dns instance ${NAME}-dns > /dev/null 2>&1
	then
		ibmcloud dns instance-create ${NAME}-dns standard-dns --resource-group ${RESOURCE_GROUP_ID}
	fi

	DNS_INSTANCE_CRN=$(ibmcloud dns instance ${NAME}-dns --output json | jq -r '.crn')

	ibmcloud dns instance-target ${DNS_INSTANCE_CRN}

	NUM_ZONES=$(ibmcloud dns zones --output json | jq -r 'def count(s): reduce s as $i (0; .+1); .[] | count(select(.name|test("^'${BASEDOMAIN}'$")))')

	if (( ${NUM_ZONES} == 0 ))
	then
		ibmcloud dns zone-create ${BASEDOMAIN} --instance ${DNS_INSTANCE_CRN}
	fi

	ZONE_ID=$(ibmcloud dns zones --output json | jq -r '.[] | select(.name|test("^'${BASEDOMAIN}'$")) | .id')

	ibmcloud dns resource-record-create ${ZONE_ID} --type A --name "api.${NAME}.${BASEDOMAIN}" --ipv4 127.0.0.1

fi
