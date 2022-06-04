#!/usr/bin/env bash

#
# (export IBMCLOUD_API_KEY=""; export IBMCLOUD_OCCMIBCCC_API_KEY=""; export IBMCLOUD_OIOCCC_API_KEY=""; export IBMCLOUD_OMAPCC_API_KEY=""; export CLUSTER_DIR=""; export IBMID=""; export CLUSTER_NAME=""; export POWERVS_REGION=""; export POWERVS_ZONE=""; export SERVICE_INSTANCE_GUID=""; export VPCREGION=""; export RESOURCE_GROUP=""; export BASEDOMAIN=""; export JENKINS_TOKEN=""; /home/OpenShift/git/powervs-hack/scripts/create-cluster.sh 2>&1 | tee output.errors)
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
ENV_VARS=( "BASEDOMAIN" "CLUSTER_DIR" "CLUSTER_NAME" "IBMCLOUD_API_KEY" "IBMCLOUD_OCCMIBCCC_API_KEY" "IBMCLOUD_OIOCCC_API_KEY" "IBMCLOUD_OMAPCC_API_KEY" "IBMID" "POWERVS_REGION" "POWERVS_ZONE" "RESOURCE_GROUP" "SERVICE_INSTANCE_GUID" "VPCREGION" )

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

if ! getent ahostsv4 ${POWERVS_REGION}.power-iaas.cloud.ibm.com > /dev/null
then
	echo "Error: POWERVS_REGION (${POWERVS_REGION}) is invalid!"
	exit 1
fi

set -x

#
# Quota check DNS
#
ibmcloud cis instance-set $(ibmcloud cis instances --output json | jq -r '.[].name')
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
if (( ${CONNECTIONS} >= 2 ))
then
	echo "Error: Cannot have 2 or more cloud connections.  You currently have ${CONNECTIONS}."
	exit 1
fi

#
# Quota check DHCP networks
#
SERVICE_INSTANCE_CRN=$(ibmcloud resource service-instances --output JSON | jq -r '.[] | select(.guid|test("'${SERVICE_INSTANCE_GUID}'")) | .id')
CLOUD_INSTANCE_ID=$(echo ${SERVICE_INSTANCE_CRN} | cut -d: -f8)
[ -z "${CLOUD_INSTANCE_ID}" ] && exit 1
echo "CLOUD_INSTANCE_ID=${CLOUD_INSTANCE_ID}"
set +x
BEARER_TOKEN=$(curl --silent -X POST "https://iam.cloud.ibm.com/identity/token" -H "content-type: application/x-www-form-urlencoded" -H "accept: application/json" -d "grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey&apikey=${IBMCLOUD_API_KEY}" | jq -r .access_token)
[ -z "${BEARER_TOKEN}" -o "${BEARER_TOKEN}" == "null" ] && exit 1
RESULT=$(curl --silent --location --request GET "https://${POWERVS_REGION}.power-iaas.cloud.ibm.com/pcloud/v1/cloud-instances/${CLOUD_INSTANCE_ID}/services/dhcp" --header 'Content-Type: application/json' --header "CRN: ${SERVICE_INSTANCE_CRN}" --header "Authorization: Bearer ${BEARER_TOKEN}")
set -x
LINES=$(echo "${RESULT}" | jq -r '.[] | .id' | wc -l)
if (( ${LINES} > 0))
then
	echo "${RESULT}" | jq -r '.[] | "\(.id) - \(.network.name)"'
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

date --utc +"%Y-%m-%dT%H:%M:%S%:z"
openshift-install create ignition-configs --dir ${CLUSTER_DIR} --log-level=debug

date --utc +"%Y-%m-%dT%H:%M:%S%:z"
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

DATE=$(date --utc +"%Y-%m-%dT%H:%M:%S%:z")
echo "${DATE}"
openshift-install create cluster --dir ${CLUSTER_DIR} --log-level=debug &
PID_INSTALL=$!
JOBS+=( "${PID_INSTALL}" )

set +e
wait ${PID_INSTALL}
RC=$?

openshift-install wait-for install-complete --dir ${CLUSTER_DIR} --log-level=debug || true
RC=$?

if [ ${RC} -gt 0 ]
then
	DEPLOYMENT_SUCCESS="failure"
else
	KUBECONFIG=${CLUSTER_DIR}/auth/kubeconfig oc --request-timeout=5s get clusterversion
	RC=$?

	if [ ${RC} -gt 0 ]
	then
		DEPLOYMENT_SUCCESS="failure"
	else
		DEPLOYMENT_SUCCESS="success"
	fi
fi

FILE=$(mktemp)
trap "/bin/rm ${FILE}" EXIT

egrep '(Creation complete|level=error)' ${CLUSTER_DIR}/.openshift_install.log > ${FILE}
CLUSTER_ID=$(jq -r '.clusterID' ${CLUSTER_DIR}/metadata.json)

OCP_VERSION=${OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE#*:}

set +x
if [ -v JENKINS_TOKEN ]
then
	# View at https://metabase.openshift-on-power.com/public/dashboard/38eff8ae-c23e-4651-8fb5-83094e3bbdb1
	curl https://jenkins.openshift-on-power.com/job/ocp_deployment_data_collector/job/deploy-register/buildWithParameters \
		--user powervs:${JENKINS_TOKEN} \
		--data EMAIL="${IBMID}" \
		--data OCP_DEPLOYMENT_MODE="ipi" \
		--data OCP_VERSION="${OCP_VERSION}" \
		--data CLUSTER_ID="${CLUSTER_ID}" \
		--data POWERVS_GUID="${SERVICE_INSTANCE_GUID}" \
		--data POWERVS_REGION="${POWERVS_REGION}" \
		--data POWERVS_ZONE="${POWERVS_ZONE}" \
		--data DEPLOYMENT_SUCCESS="${DEPLOYMENT_SUCCESS}" \
		--data DEPLOYMENT_LOG="$(cat ${FILE})" \
		--data DEPLOYMENT_DATE_TIME="${DATE}"
fi
set -x

if [ -v CLEANUP ]
then
	SAVE_DIR=$(mktemp --directory)

	rsync -av ${CLUSTER_DIR}/ ${SAVE_DIR}/${CLUSTER_DIR}/

	rsync -av ${SAVE_DIR}/${CLUSTER_DIR}/ ${CLUSTER_DIR}/
	./bin/openshift-install --dir=${CLUSTER_DIR} destroy cluster --log-level=debug
	sleep 1m
	rsync -av ${SAVE_DIR}/${CLUSTER_DIR}/ ${CLUSTER_DIR}/
	./bin/openshift-install --dir=${CLUSTER_DIR} destroy cluster --log-level=debug
	sleep 1m
	rsync -av ${SAVE_DIR}/${CLUSTER_DIR}/ ${CLUSTER_DIR}/
	./bin/openshift-install --dir=${CLUSTER_DIR} destroy cluster --log-level=debug

	/bin/rm -rf ${SAVE_DIR}
fi
