#!/usr/bin/env bash

declare -a ENV_VARS
ENV_VARS=( "CLUSTER_DIR" )

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

ARG_NAME=${1-}
INSTANCE_NAME=""

case "${ARG_NAME}" in
	"")
		true
	;;
	"hamzy-CI")
		export NETWORK_NAME=""
		export INSTANCE_NAME="hamzy-CI"
	;;
	*)
		echo "Error: Unexpected argument ${ARG_NAME}"
		exit 1
	;;
esac

if [ -z "${ARG_NAME}" ]
then
	export INFRA_ID=$(jq -r '.infraID' ${CLUSTER_DIR}/metadata.json)

	while true
	do
		export NETWORK_NAME=$(ibmcloud pi instance ${INFRA_ID}-master-0 --json | jq -r '.addresses[].networkName')
		if [ -n "${NETWORK_NAME}" ]
		then
			break
		fi
	done

	export INSTANCE_NAME="${INFRA_ID}-jumpbox"
fi

USER=$(id -un)

VPC_INSTANCE_NAME="${INFRA_ID}-vs1"
VPC_ID=$(ibmcloud is vpcs --output json | jq -r '.[] | select (.name|test("'${INFRA_ID}'")) | .id')
VPC_SUBNET="vpc-subnet-${INFRA_ID}"
VPC_SUBNET_ZONE=$(ibmcloud is subnet ${VPC_SUBNET} --output json | jq -r '.zone.name')
IMAGE_NAME=$(ibmcloud is images --output json | jq -r '.[] | select (.name|test("ibm-centos.*amd64")) | select (.status|test("available")) | .name')
RESOURCE_GROUP=$(jq -r '.powervs.powerVSResourceGroup' ${CLUSTER_DIR}/metadata.json)

COUNT_INSTANCES=$(ibmcloud is instances --output json | jq -r '.[] | select (.name|test("'${INFRA_ID}'")) | length')
if [ "${COUNT_INSTANCES}" == "" ]
then
	COUNT_INSTANCES=0
fi

if (( ${COUNT_INSTANCES} == 0 ))
then
	ibmcloud is instance-create ${VPC_INSTANCE_NAME} ${VPC_ID} ${VPC_SUBNET_ZONE} cx2-2x4 ${VPC_SUBNET} --keys ${USER}-key --image ${IMAGE_NAME} --resource-group-name ${RESOURCE_GROUP}
fi

NET_IFACE_ID=$(ibmcloud is instance ${VPC_INSTANCE_NAME} --output json | jq -r '.primary_network_interface.id')

ibmcloud is floating-ip-reserve ${VPC_INSTANCE_NAME}-floating-ip --nic ${NET_IFACE_ID}

SECURITY_GROUP_NAME=$(ibmcloud is instance ${VPC_INSTANCE_NAME} --output json | jq -r '.primary_network_interface.security_groups[].name')

ibmcloud is security-group-rule-add ${SECURITY_GROUP_NAME} inbound tcp --port-min 22 --port-max 22 --remote '0.0.0.0/0'
ibmcloud is security-group-rule-add ${SECURITY_GROUP_NAME} inbound icmp --remote '0.0.0.0/0'

if ! ibmcloud pi network ${USER}-public-network
then
	ibmcloud pi network-create-public ${USER}-public-network --dns-servers "1.1.1.1 9.9.9.9 8.8.8.8"
fi

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

if ! ibmcloud pi instance ${INSTANCE_NAME}
then
	CMD="ibmcloud pi instance-create ${INSTANCE_NAME} --image CentOS-Stream-8 --memory 8 --key-name ${USER}-key --network ${USER}-public-network"
	if [ -n "${NETWORK_NAME}" ]
	then	
		CMD="${CMD} --network ${NETWORK_NAME}"
	fi       
	CMD="${CMD} -storage-type tier1"
	eval ${CMD}
fi

while true
do
	set +e
	ibmcloud pi instance-get-console ${INSTANCE_NAME}
	RC=$?
	set -e
	if [ ${RC} -eq 0 ]
	then
		break
	fi
	sleep 30s
done

while true
do
	export IP=$(ibmcloud pi instance ${INSTANCE_NAME} --json | jq -r '.networks[] | select(.networkName|test("'${USER}'-public-network")) | .externalIP')
	if [ $? -eq 0 ]
	then
		break
	fi
	sleep 30s
done

set +e
ssh-keygen -f ~/.ssh/known_hosts -R ${IP}
ssh-keyscan ${IP} >> ~/.ssh/known_hosts
ssh -A cloud-user@${IP}

#
# $ sudo dnf install -y tmux jq
# $ curl --location --remote-name https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/4.11.0-fc.3/openshift-install-linux.tar.gz; tar xvfz openshift-install-linux.tar.gz; mkdir -p ./bin; /bin/cp ./openshift-install ./bin/
# $ (set -xe; mkdir -p ~/.powervs/; FILE=$(mktemp); trap "/bin/rm ${FILE}" EXIT; ID="hamzy@us.ibm.com"; APIKEY=${IBMCLOUD_API_KEY}; REGION="syd"; ZONE="syd04"; echo '{}' | jq -r --arg ID "${ID}" --arg APIKEY "${APIKEY}" --arg REGION "${REGION}" --arg ZONE "${ZONE}" ' .id = $ID | .apikey = $APIKEY | .region = $REGION | .zone = $ZONE ' > ${FILE}; /bin/cp ${FILE} ~/.powervs/config.json)
# $ curl --location --remote-name https://download.clis.cloud.ibm.com/ibm-cloud-cli/2.9.0/IBM_Cloud_CLI_2.9.0_ppc64le.tar.gz; tar xvzf IBM_Cloud_CLI_2.9.0_ppc64le.tar.gz; ./Bluemix_CLI/install
# $ for I in infrastructure-service power-iaas cloud-internet-services cloud-object-storage dl-cli dns; do ibmcloud plugin install ${I}; done
#
