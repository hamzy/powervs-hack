#!/usr/bin/env bash

#
# Usage example:
#
# (export IBMCLOUD_API_KEY=""; export IBMCLOUD_OCCMICCC_API_KEY=""; export IBMCLOUD_OIOCCC_API_KEY=""; export IBMCLOUD_OCCDIPCCC_API_KEY=""; export IBMCLOUD_OMAPCC_API_KEY=""; export CLUSTER_DIR=""; export IBMID=""; export CLUSTER_NAME=""; export POWERVS_REGION=""; export POWERVS_ZONE=""; export SERVICE_INSTANCE_GUID=""; export VPCREGION=""; export RESOURCE_GROUP=""; export BASEDOMAIN=""; export JENKINS_TOKEN=""; /home/OpenShift/git/powervs-hack/scripts/create-cluster.sh 2>&1 | tee output.errors)
#

#
# Steps taken:
#
# openshift-install create install-config
# openshift-install create ignition-configs
# openshift-install create manifests
# openshift-install create cluster
# openshift-install wait-for install-complete
#

USE_CAPI=true
TEST_QUOTA_DNS=false
TEST_QUOTA_CLOUD_CONNECTIONS=false
TEST_QUOTA_DHCP=false
TEST_QUOTA_IMAGE_IMPORT=true

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
ENV_VARS=( "BASEDOMAIN" "CLUSTER_DIR" "CLUSTER_NAME" "IBMCLOUD_API_KEY" "IBMCLOUD_OCCMICCC_API_KEY" "IBMCLOUD_OIOCCC_API_KEY" "IBMCLOUD_OCCDIPCCC_API_KEY" "IBMCLOUD_OMAPCC_API_KEY" "IBMID" "POWERVS_REGION" "POWERVS_ZONE" "RESOURCE_GROUP" "SERVICE_INSTANCE_GUID" "VPCREGION" )

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

# PROBLEM:
# export IBMCLOUD_REGION=${VPCREGION} # ${POWERVS_REGION}
# export IBMCLOUD_ZONE=${POWERVS_ZONE}

# https://github.com/openshift/installer/blob/master/data/data/coreos/rhcos.json#L267
# The format is the-contents-of-the-bucket-variable / the-contents-of-the-object-variable
#export OPENSHIFT_INSTALL_OS_IMAGE_OVERRIDE="rhcos-powervs-images-${VPCREGION}/rhcos-413-92-202304131328-0-ppc64le-powervs.ova.gz"

#export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="quay.io/openshift-release-dev/ocp-release:4.11.47-ppc64le"
#export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="quay.io/openshift-release-dev/ocp-release:4.12.29-ppc64le"
#export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="quay.io/openshift-release-dev/ocp-release:4.13.9-ppc64le"
# registry.ci.openshift.org/ocp-multi/4.16-art-latest-multi:4.16.0-0.nightly-multi-2024-02-22-055830
#export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="quay.io/openshift-release-dev/ocp-release-nightly@sha256:929563ce4e99bbb42661b74946ded25d753118c8203cedbc6c7bb48f7f2b5667"
#export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="registry.ci.openshift.org/ocp-ppc64le/release-ppc64le:4.15.0-0.nightly-ppc64le-2024-02-17-002157"
#export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="registry.ci.openshift.org/ocp-ppc64le/release-ppc64le:4.16.0-0.nightly-ppc64le-2024-03-19-080310"
export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="registry.ci.openshift.org/ocp-ppc64le/release-ppc64le:4.16.0-0.nightly-ppc64le-2024-03-23-105659"
#export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="quay.io/hamzy/openshift-release:powervs-cluster-api"

export PATH=${PATH}:$(pwd)/bin
export BASE64_API_KEY=$(echo -n ${IBMCLOUD_API_KEY} | base64)
export KUBECONFIG=${CLUSTER_DIR}/auth/kubeconfig
export IC_API_KEY=${IBMCLOUD_API_KEY}

if ! hash jq 1>/dev/null 2>&1
then
	echo "Error: Missing jq program!"
	exit 1
fi

# Uncomment for even moar debugging!
#export TF_LOG_PROVIDER=TRACE
#export TF_LOG=TRACE
#export TF_LOG_PROVIDER=DEBUG
#export TF_LOG=DEBUG
#export TF_LOG_PATH=/tmp/tf.log
#export IBMCLOUD_TRACE=true

DNSRESOLV=""
hash getent 1>/dev/null 2>&1 && DNSRESOLV="getent ahostsv4"
hash dig 1>/dev/null 2>&1 && DNSRESOLV="dig +short"
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

set -x

if ${TEST_QUOTA_DNS}
then
	#
	# Quota check DNS
	#
	if ibmcloud cis 1>/dev/null 2>&1
	then
		# Currently, only support on x86_64 arch :(
		ibmcloud cis instance-set $(ibmcloud cis instances --output json | jq -r '.[].name')
		export DNS_DOMAIN_ID=$(ibmcloud cis domains --output json | jq -r '.[].id')
		RECORDS=$(ibmcloud cis dns-records ${DNS_DOMAIN_ID} --output json | jq -r '.[] | select (.name|test("'${CLUSTER_NAME}'.*")) | "\(.name) - \(.id)"')
		if [ -n "${RECORDS}" ]
		then
			echo "${RECORDS}"
			exit 1
		fi
	fi
fi

if ${TEST_QUOTA_CLOUD_CONNECTIONS}
then
	#
	# Quota check cloud connections
	#
	CONNECTIONS=$(ibmcloud pi cloud-connection list --json | jq -r '.cloudConnections|length')
	if (( ${CONNECTIONS} >= 2 ))
	then
		echo "Error: Cannot have 2 or more cloud connections.  You currently have ${CONNECTIONS}."
		exit 1
	fi
fi

if ${TEST_QUOTA_DHCP}
then
	#
	# Quota check DHCP networks
	#
	SERVICE_INSTANCE_CRN=$(ibmcloud resource service-instances --output JSON | jq -r '.[] | select(.guid|test("'${SERVICE_INSTANCE_GUID}'")) | .crn')
	CLOUD_INSTANCE_ID=$(echo ${SERVICE_INSTANCE_CRN} | cut -d: -f8)
	[ -z "${CLOUD_INSTANCE_ID}" ] && exit 1
	echo "CLOUD_INSTANCE_ID=${CLOUD_INSTANCE_ID}"
	set +x
	BEARER_TOKEN=$(curl --silent -X POST "https://iam.cloud.ibm.com/identity/token" -H "content-type: application/x-www-form-urlencoded" -H "accept: application/json" -d "grant_type=urn%3Aibm%3Aparams%3Aoauth%3Agrant-type%3Aapikey&apikey=${IBMCLOUD_API_KEY}" | jq -r .access_token)
	[ -z "${BEARER_TOKEN}" ] && exit 1
	[ "${BEARER_TOKEN}" == "null" ] && exit 1
	RESULT=$(curl --silent --location --request GET "https://${POWERVS_REGION}.power-iaas.cloud.ibm.com/pcloud/v1/cloud-instances/${CLOUD_INSTANCE_ID}/services/dhcp" --header 'Content-Type: application/json' --header "CRN: ${SERVICE_INSTANCE_CRN}" --header "Authorization: Bearer ${BEARER_TOKEN}")
	set -x
	LINES=$(echo "${RESULT}" | jq -r '.[] | .id' | wc -l)
	if (( ${LINES} > 0))
	then
		echo "${RESULT}" | jq -r '.[] | "\(.id) - \(.network.name)"'
		exit 1
	fi
fi

if ${TEST_QUOTA_IMAGE_IMPORT}
then
	#
	# Quota check for image imports
	#
	JOBS=$(ibmcloud pi job list --operation-action imageImport --json | jq -r '.jobs[] | select (.status.state|test("running")) | .id')
	if [ -n "${JOBS}" ]
	then
		echo "${JOBS}"
		exit 1
	fi
fi

declare -a JOBS

trap 'echo "Killing JOBS"; for PID in ${JOBS[@]}; do kill -9 ${PID} >/dev/null 2>&1 || true; done' TERM

#
# Recreate saved installer PowerVS session data
#
export PI_SESSION_DIR=~/.powervs
if [ -d ${PI_SESSION_DIR} ]
then
	/bin/rm -rf ${PI_SESSION_DIR}
fi
mkdir ${PI_SESSION_DIR}
(
	set -euo pipefail
	FILE=$(mktemp)
	trap "/bin/rm ${FILE}" EXIT
	# Create the json file with jq
	echo '{}' | jq -r \
		--arg ID "${IBMID}" \
		--arg APIKEY "${IBMCLOUD_API_KEY}" \
		--arg REGION "${POWERVS_REGION}" \
		--arg ZONE "${POWERVS_ZONE}" \
		--arg SERVICE_INSTANCE "${SERVICE_INSTANCE_GUID}" \
		--arg RESOURCE_GROUP "${RESOURCE_GROUP}" \
		' .id = $ID
		| .apikey = $APIKEY
		| .region = $REGION
		| .zone = $ZONE
		| .serviceinstance = $SERVICE_INSTANCE
		| .resourcegroup = $RESOURCE_GROUP
		' > ${FILE}
	/bin/cp ${FILE} ${PI_SESSION_DIR}/config.json
)
#		' .id = $ID
#		| .apikey = $APIKEY
#		| .region = $REGION
#		| .zone = $ZONE
#		| .serviceinstance = $SERVICE_INSTANCE
#		| .resourcegroup = $RESOURCE_GROUP
#		| .resourcegroup = "Default"
#		' > ${FILE}
#/bin/rm -rf ${PI_SESSION_DIR}

#
# Recreate openshift-installer's cluster directory
#
rm -rf ${CLUSTER_DIR}
mkdir ${CLUSTER_DIR}

init_ibmcloud

#SSH_KEY=$(cat ~/.ssh/id_rsa.pub)
SSH_KEY=$(cat ~/.ssh/id_installer_rsa.pub)

#
# perl -pi -e 'chomp if eof' < ~/.pullSecretCompact | xclip -i -selection clipboard
#
PULL_SECRET=$(cat ~/.pullSecret)

function validate_pull_secret() {
  set +eux
  runtime=""
  which docker 1>/dev/null 2>&1
  if [[ $? == 0 ]]; then
     runtime="docker"
  fi
  which podman 1>/dev/null 2>&1
  if [[ $? == 0 && -z ${runtime} ]]; then
     runtime="podman"
  fi
  if [[ -z ${runtime} ]]; then
     echo "Warning: Neither docker nor podman is installed hence we
     cannot check whether the pull secret is latest"
	 return
  fi
  if [[ -n {OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE} ]]; then
    ${runtime} pull ${OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE} --authfile=$1 1>/dev/null 2>&1
  else
    ${runtime} pull registry.ci.openshift.org/origin/release:4.16 --authfile=$1 1>/dev/null 2>&1
  fi
  if [[ $? != 0 ]]; then
    echo "Error: Pull secret is invalid!"
    exit 1
  fi

  # rmi without -f. In case another container uses the image, retain it.
  if [[ -n {OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE} ]]; then
    ${runtime} rmi ${OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE} 1>/dev/null 2>&1
  else
    ${runtime} rmi registry.ci.openshift.org/origin/release:4.16 1>/dev/null 2>&1
  fi
  set -eux
}
validate_pull_secret "/root/.pullSecret"

#openshift-install create install-config --dir ${CLUSTER_DIR} --log-level=debug
#exit 0

#
# Create the openshift-installer's install configuration file
#
cat << ___EOF___ > ${CLUSTER_DIR}/install-config.yaml
apiVersion: v1
baseDomain: "${BASEDOMAIN}"
compute:
- architecture: ppc64le
  hyperthreading: Enabled
  name: worker
# VERSION 1
  platform: {}
# VERSION 2
# platform:
#   powervs:
#     sysType: e980
# VERSION 3
# platform:
#   powervs:
#     processors: 1
#     procType: "Capped"
# VERSION 4
# platform:
#   powervs:
#     processors: 1
#     procType: "Dedicated"
#     sysType: e980
  replicas: 3
# replicas: 0
controlPlane:
  architecture: ppc64le
  hyperthreading: Enabled
  name: master
# VERSION 1
  platform: {}
# VERSION 2
# platform:
#   powervs:
#     sysType: e980
# VERSION 3
# platform:
#   powervs:
#     processors: 1
#     procType: "Capped"
# VERSION 4
# platform:
#   powervs:
#     processors: 6
#     procType: "Dedicated"
#     sysType: e980
# replicas: 1
  replicas: 3
metadata:
  creationTimestamp: null
  name: "${CLUSTER_NAME}"
networking:
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  machineNetwork:
  - cidr: 192.168.220.0/24
# networkType: OpenShiftSDN
  networkType: OVNKubernetes
  serviceNetwork:
  - 172.30.0.0/16
platform:
  powervs:
    userID: ${IBMID}
    powervsResourceGroup: ${RESOURCE_GROUP}
    region: ${POWERVS_REGION}
#   vpcName: rdr-hamzy-test-us-south-vpc
#   vpcRegion: ${VPCREGION}
#   vpcSubnets:
#     - subnet1
#     - subnet2
#     - subnet3
    zone: ${POWERVS_ZONE}
    serviceInstanceGUID: ${SERVICE_INSTANCE_GUID}
featureSet: CustomNoUpgrade
featureGates:
   - ClusterAPIInstall=true
publish: External
#publish: Internal
pullSecret: '${PULL_SECRET}'
sshKey: |
  ${SSH_KEY}
___EOF___

if ! ${USE_CAPI}
then
	sed -i -e '/^featureSet/d' -e'/^featureGates/d' -e '/ClusterAPIInstall/d' ${CLUSTER_DIR}/install-config.yaml
fi

#
# We use manual credentials mode
#
sed -i '/credentialsMode/d' ${CLUSTER_DIR}/install-config.yaml
sed -i '/^baseDomain:.*$/a credentialsMode: Manual' ${CLUSTER_DIR}/install-config.yaml

date --utc +"%Y-%m-%dT%H:%M:%S%:z"
#openshift-install create ignition-configs --dir ${CLUSTER_DIR} --log-level=debug

date --utc +"%Y-%m-%dT%H:%M:%S%:z"
openshift-install create manifests --dir ${CLUSTER_DIR} --log-level=debug
#exit 0

#
# Create three cluster operator's configuration files
#
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
    IBMCLOUD_APIKEY=${IBMCLOUD_OCCMICCC_API_KEY}
  ibmcloud_api_key: ${IBMCLOUD_OCCMICCC_API_KEY}
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

cat << ___EOF___ > ${CLUSTER_DIR}/manifests/openshift-cluster-csi-drivers-ibm-powervs-cloud-credentials-credentials.yaml
apiVersion: v1
kind: Secret
metadata:
  creationTimestamp: null
  name: ibm-powervs-cloud-credentials
  namespace: openshift-cluster-csi-drivers
stringData:
  ibm-credentials.env: |-
    IBMCLOUD_AUTHTYPE=iam
    IBMCLOUD_APIKEY=${IBMCLOUD_OCCDIPCCC_API_KEY}
  ibmcloud_api_key: ${IBMCLOUD_OCCDIPCCC_API_KEY}
type: Opaque
___EOF___

cat << ___EOF___ > ${CLUSTER_DIR}/manifests/openshift-image-registry-installer-cloud-credentials-credentials.yaml
apiVersion: v1
kind: Secret
metadata:
  creationTimestamp: null
  name: installer-cloud-credentials
  namespace: openshift-image-registry
stringData:
  ibm-credentials.env: |-
    IBMCLOUD_AUTHTYPE=iam
    IBMCLOUD_APIKEY=${IBMCLOUD_OIRICCC_API_KEY}
  ibmcloud_api_key: ${IBMCLOUD_OIRICCC_API_KEY}
type: Opaque
___EOF___

DATE=$(date --utc +"%Y-%m-%dT%H:%M:%S%:z")
echo "${DATE}"
openshift-install create cluster --dir ${CLUSTER_DIR} --log-level=debug # &
#echo openshift-install create cluster --dir ${CLUSTER_DIR} --log-level=debug &
exit 0
PID_INSTALL=$!
JOBS+=( "${PID_INSTALL}" )

set +e
wait ${PID_INSTALL}
RC=$?

#
# Maybe the first time took too long and it is possible to wait for a second
# attempt to complete?
#
#openshift-install wait-for install-complete --dir ${CLUSTER_DIR} --log-level=debug || true
RC=$?

if [ ${RC} -gt 0 ]
then
	DEPLOYMENT_SUCCESS="failure"
else
	set +x
	OC_OUTPUT=$(
		DEBUG=true

		CV_FILE=$(mktemp)
		F_FILE=$(mktemp)
		trap "/bin/rm ${CV_FILE} ${F_FILE}" EXIT

		oc --request-timeout=5s get clusterversion -o json > ${CV_FILE} 2>/dev/null
		RC=$?
		if ${DEBUG}
		then
			oc --request-timeout=5s get clusterversion 2>/dev/null > /tmp/get-clusterversion.output
		fi
		if [ ${RC} -gt 0 ]
		then
			exit 1
		fi
		if ${DEBUG}
		then
			echo "===== BEGIN: oc get clusterversion: CV_FILE =====" >> /tmp/get-clusterversion.output
			cat ${CV_FILE} >> /tmp/get-clusterversion.output
			echo "===== END: oc get clusterversion: CV_FILE =====" >> /tmp/get-clusterversion.output
		fi
		jq -r '.items[].status.conditions[] | select (.status|test("False"))' ${CV_FILE} > ${F_FILE}
		RC=$?
		if ${DEBUG}
		then
			echo "===== BEGIN: oc get clusterversion: F_FILE =====" >> /tmp/get-clusterversion.output
			cat ${F_FILE} >> /tmp/get-clusterversion.output
			echo "===== END: oc get clusterversion: F_FILE =====" >> /tmp/get-clusterversion.output
		fi
		if [ ${RC} -gt 0 ]
		then
			exit 1
		fi
		AVAILABLE=$(jq -r 'select (.type|test("Available"))' ${F_FILE})
		echo ${AVAILABLE}
	)
	RC=$?
	set -x

	echo "OC_OUTPUT=${OC_OUTPUT}"

	if [ ${RC} -gt 0 ]
	then
		DEPLOYMENT_SUCCESS="failure"
	else
		if [ "${OC_OUTPUT}" == "" ]
		then
			DEPLOYMENT_SUCCESS="success"
		else
			DEPLOYMENT_SUCCESS="failure"
		fi
	fi

	if [ -f /tmp/get-clusterversion.output ]
	then
		/bin/cp /tmp/get-clusterversion.output ${CLUSTER_DIR}/
	fi
fi

if false
then
	if [ -z "$(jq -r '.powervs["vpcRegion"]' ${CLUSTER_DIR}/metadata.json)" ]
	then
		#
		# Fix bug where vpcRegion is not set but needed for destroy logic
		#
		(
			set -xe
			FILE=$(mktemp)
			trap "/bin/rm ${FILE}" EXIT
			jq -r --arg VPCREGION "${VPCREGION}" \
				' .powervs["vpcRegion"] = $VPCREGION' \
				< ${CLUSTER_DIR}/metadata.json \
				> ${FILE}
			/bin/cp ${FILE} ${CLUSTER_DIR}/metadata.json
		)
	fi
fi

JENKINS_FILE=$(mktemp)
trap "/bin/rm ${JENKINS_FILE}" EXIT

egrep '(Creation complete|level=error|: [0-9ms]*")' ${CLUSTER_DIR}/.openshift_install.log > ${JENKINS_FILE}
sed -i -r -e 's,level=error(.* provider[^:]*: ),level=debug\1,' ${JENKINS_FILE}
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
		--data DEPLOYMENT_LOG="$(cat ${JENKINS_FILE})" \
		--data DEPLOYMENT_DATE_TIME="${DATE}"
fi
set -x

if [ -v CLEANUP ]
then
	BASE_CLUSTER_DIR=$(basename ${CLUSTER_DIR})
	SAVE_DIR=$(mktemp --directory)

	rsync -av ${CLUSTER_DIR}/ ${SAVE_DIR}/${BASE_CLUSTER_DIR}/
	./bin/openshift-install --dir=${SAVE_DIR}/${BASE_CLUSTER_DIR}/ destroy cluster --log-level=debug
	sleep 1m

	rsync -av ${CLUSTER_DIR}/ ${SAVE_DIR}/${BASE_CLUSTER_DIR}/
	./bin/openshift-install --dir=${SAVE_DIR}/${BASE_CLUSTER_DIR}/ destroy cluster --log-level=debug
	sleep 1m

	rsync -av ${CLUSTER_DIR}/ ${SAVE_DIR}/${BASE_CLUSTER_DIR}/
	./bin/openshift-install --dir=${SAVE_DIR}/${BASE_CLUSTER_DIR}/ destroy cluster --log-level=debug

	/bin/rm -rf ${SAVE_DIR}
fi
