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

if ! ibmcloud pi network hamzy-public-network
then
	ibmcloud pi network-create-public hamzy-public-network --dns-servers "1.1.1.1 9.9.9.9 8.8.8.8"
fi

CENTOS_ID=$(ibmcloud pi images --json | jq -r '.[] | select (.name|test("CentOS-Stream-8")) | .imageID')
if [ -z "${CENTOS_ID}" ]
then
	ibmcloud pi image-create CentOS-Stream-8

	CENTOS_ID=$(ibmcloud pi images --json | jq -r '.[] | select (.name|test("CentOS-Stream-8")) | .imageID')

	STATE="queued"
	while [ "${STATE}" == "queued" ]
	do
		sleep 15s
		STATE=$(ibmcloud pi image ${CENTOS_ID} --json | jq -r '.state')
	done
fi

if ! ibmcloud pi instance ${INSTANCE_NAME}
then
	CMD="ibmcloud pi instance-create ${INSTANCE_NAME} --image CentOS-Stream-8 --memory 8 --key-name hamzy-key --network hamzy-public-network"
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
	export IP=$(ibmcloud pi instance ${INSTANCE_NAME} --json | jq -r '.networks[] | select(.networkName|test("hamzy-public-network")) | .externalIP')
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
