#!/usr/bin/env bash

#
# (export CLUSTER_DIR="./ocp-test"; export IBMID="hamzy@us.ibm.com"; export CLUSTER_NAME="rdr-hamzy-test"; export POWERVS_REGION="lon"; export POWERVS_ZONE="lon04"; export SERVICE_INSTANCE="powervs-ipi-lon04"; export VPCREGION="eu-gb"; export VPC="powervs-ipi"; export SUBNET="subnet2"; /home/OpenShift/git/powervs-hack/scripts/create-cluster.sh 2>&1 | tee output.errors)
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

function init_ibmcloud()
{
	if ! ibmcloud iam oauth-tokens 1>/dev/null 2>&1
	then
		ibmcloud login --apikey "${IBMCLOUD_API_KEY}" -r ${VPCREGION}
	fi
}

declare -a ENV_VARS
ENV_VARS=( "CLUSTER_DIR" "CLUSTER_NAME" "IBMCLOUD_API_KEY" "IBMCLOUD_OCCMIBCCC_API_KEY" "IBMCLOUD_OIOCCC_API_KEY" "IBMCLOUD_OMAPCC_API_KEY" "IBMID" "POWERVS_REGION" "POWERVS_ZONE" "SERVICE_INSTANCE_GUID" "VPCREGION" "BASEDOMAIN" "RESOURCE_GROUP" )
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

export IBMCLOUD_REGION=${POWERVS_REGION}
export IBMCLOUD_ZONE=${POWERVS_ZONE}

export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="quay.io/openshift-release-dev/ocp-release-nightly:4.11.0-0.nightly-ppc64le-2022-05-13-170447"

export PATH=${PATH}:$(pwd)/bin
export BASE64_API_KEY=$(echo -n ${IBMCLOUD_API_KEY} | base64)
export KUBECONFIG=${CLUSTER_DIR}/auth/kubeconfig
export IC_API_KEY=${IBMCLOUD_API_KEY}

#export TF_LOG_PROVIDER=TRACE
#export TF_LOG=TRACE
#export TF_LOG_PATH=/tmp/tf.log
#export IBMCLOUD_TRACE=true

set -x

#
# Quota check DNS
#
export DNS_DOMAIN_ID=$(ibmcloud cis domains --output json | jq -r '.[].id')
RECORDS=$(ibmcloud cis dns-records ${DNS_DOMAIN_ID} --output json | jq -r '.[] | select (.name|test("'${CLUSTER_NAME}'.*")) | "\(.name) - \(.id)"')
if [ -n "${RECORDS}" ]
then
	echo "${RECORDS}"
	exit 1
fi

#
# Quota check cloud connections
#
CONNECTIONS=$(ibmcloud pi connections --json | jq -r '.Payload.cloudConnections|length')
if (( ${CONNECTIONS} >= 1 ))
then
	echo "Error: Cannot have 1 or more cloud connections.  You currently have ${CONNECTIONS}."
	exit 1
fi

#
# Quota check for image imports
#
JOBS=$(ibmcloud pi jobs --operation-action imageImport --json | jq -r '.Payload.jobs[] | select (.status.state|test("running")) | .id')
if [ -n "${JOBS}" ]
then
	echo "${JOBS}"
	exit 1
fi

declare -a JOBS

trap 'echo "Killing JOBS"; for PID in ${JOBS[@]}; do kill -9 ${PID} >/dev/null 2>&1 || true; done' TERM

if [ -f ~/.powervs/config.json ]
then
	/bin/rm ~/.powervs/config.json
fi
if [ -d ~/.powervs/ ]
then
	/bin/rm -rf ~/.powervs/
fi

init_ibmcloud

rm -rf ${CLUSTER_DIR}
mkdir ${CLUSTER_DIR}

SSH_KEY=$(cat ~/.ssh/id_rsa.pub)
PULL_SECRET=$(cat ~/.pullSecret)

cat << ___EOF___ > ${CLUSTER_DIR}/install-config.yaml
apiVersion: v1
baseDomain: "${BASEDOMAIN}"
compute:
- architecture: ppc64le
  hyperthreading: Enabled
  name: worker
  platform: {}
  replicas: 3
controlPlane:
  architecture: ppc64le
  hyperthreading: Enabled
  name: master
  platform: {}
  replicas: 3
metadata:
  creationTimestamp: null
  name: "${CLUSTER_NAME}"
networking:
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  machineNetwork:
  - cidr: 192.168.0.0/16
  networkType: OpenShiftSDN
  serviceNetwork:
  - 172.30.0.0/16
platform:
  powervs:
    userid: "${IBMID}"
    powervsResourceGroup: "${RESOURCE_GROUP}"
    region: "${POWERVS_REGION}"
    vpcRegion: "${VPCREGION}"
    zone: "${POWERVS_ZONE}"
    serviceInstanceID: "${SERVICE_INSTANCE_GUID}"
publish: External
pullSecret: '${PULL_SECRET}'
sshKey: |
  ${SSH_KEY}
___EOF___

sed -i '/credentialsMode/d' ${CLUSTER_DIR}/install-config.yaml
sed -i '/^baseDomain:.*$/a credentialsMode: Manual' ${CLUSTER_DIR}/install-config.yaml

date
openshift-install create ignition-configs --dir ${CLUSTER_DIR} --log-level=debug

date
openshift-install create manifests --dir ${CLUSTER_DIR} --log-level=debug

cat << ___EOF___ > ${CLUSTER_DIR}/manifests/openshift-cloud-controller-manager-ibm-cloud-credentials-credentials.yaml
apiVersion: v1
kind: Secret
metadata:
  creationTimestamp: null
  name: ibm-cloud-credentials
  namespace: openshift-cloud-controller-manager
stringData:
  ibm-credentials.env: |-
    IBMCLOUD_AUTHTYPE=iam
    IBMCLOUD_APIKEY=${IBMCLOUD_OCCMIBCCC_API_KEY}
  ibmcloud_api_key: ${IBMCLOUD_OCCMIBCCC_API_KEY}
type: Opaque
___EOF___

cat << ___EOF___ > ${CLUSTER_DIR}/manifests/openshift-ingress-operator-cloud-credentials-credentials.yaml
apiVersion: v1
kind: Secret
metadata:
  creationTimestamp: null
  name: cloud-credentials
  namespace: openshift-ingress-operator
stringData:
  ibm-credentials.env: |-
    IBMCLOUD_AUTHTYPE=iam
    IBMCLOUD_APIKEY=${IBMCLOUD_OIOCCC_API_KEY}
  ibmcloud_api_key: ${IBMCLOUD_OIOCCC_API_KEY}
type: Opaque
___EOF___

cat << ___EOF___ > ${CLUSTER_DIR}/manifests/openshift-machine-api-powervs-credentials-credentials.yaml
apiVersion: v1
kind: Secret
metadata:
  creationTimestamp: null
  name: powervs-credentials
  namespace: openshift-machine-api
stringData:
  ibm-credentials.env: |-
    IBMCLOUD_AUTHTYPE=iam
    IBMCLOUD_APIKEY=${IBMCLOUD_OMAPCC_API_KEY}
  ibmcloud_api_key: ${IBMCLOUD_OMAPCC_API_KEY}
type: Opaque
___EOF___

date
openshift-install create cluster --dir ${CLUSTER_DIR} --log-level=debug &
PID_INSTALL=$!
JOBS+=( "${PID_INSTALL}" )

wait ${PID_INSTALL}
