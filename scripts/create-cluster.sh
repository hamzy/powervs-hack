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

function create_ibm_cloud_credentials_secret()
{
	log_to_file /tmp/create-ibm-cloud-credentials-secret.log
	RC=1
	while [ ${RC} -gt 0 ]
	do
		sleep 1m
		set +e
		oc --request-timeout=10s get secret/cloud-credentials -n openshift-ingress-operator > /dev/null
		RC=$?
		set -e
		echo "RC=${RC}"
	done
	oc get secret/cloud-credentials -n openshift-ingress-operator -o json \
		| sed	-e 's,"cloud-credentials","ibm-cloud-credentials",' \
			-e 's,"openshift-ingress-operator","openshift-cloud-controller-manager",' \
		| oc create -f -
	echo "create_ibm_cloud_credentials_secret: FINISHED!"
}

function init_ibmcloud()
{
	if ! ibmcloud iam oauth-tokens 1>/dev/null 2>&1
	then
		ibmcloud login --apikey "${IBMCLOUD_API_KEY}" -r ${VPCREGION}
	fi
}

function fix_load_balancer_hostname()
{	
	log_to_file /tmp/fix-load-balancer-hostname.log

	CLUSTER_ID=$(jq -r '.infraID' ${CLUSTER_DIR}/metadata.json)
	HOSTNAME_EXTERNAL="apps.${CLUSTER_NAME}.scnl-ibm.com"

	FOUND=false
	FILE=$(mktemp)

	while ! ${FOUND}
	do
		sleep 1m
		ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("^kube-'${CLUSTER_ID}'"))' > ${FILE}
		RC=$?
		if [ ${RC} -eq 0 ]
		then
			LINE_OUTPUT=$(wc -l ${FILE})
			RC=$?
			if [ ${RC} -eq 0 ]
			then
				LINES=$(echo "${LINE_OUTPUT}" | cut -f1 -d' ')
				RC=$?
				if (( ${LINES} > 0 ))
				then
					FOUND=true
				fi
			fi
		fi
	done

	HOSTNAME_LB=$(ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("^kube-'${CLUSTER_ID}'")) | .hostname')
	ID_DOMAIN=$(ibmcloud cis domains --output json | jq -r '.[] | select (.name|test("^scnl-ibm.com$")) | .id')
	ID_HOSTNAME=$(ibmcloud cis dns-records ${ID_DOMAIN} --output json | jq -r '.[] | select (.name|test("'${HOSTNAME_EXTERNAL}'$")) | .id')
	if [ -n "${ID_HOSTNAME}" ]
	then
		ibmcloud cis dns-record-update ${ID_DOMAIN} ${ID_HOSTNAME} --json '{ "name": "*.'${HOSTNAME_EXTERNAL}'", "type": "CNAME", "content": "'${HOSTNAME_LB}'" }'
	else
		ibmcloud cis dns-record-create ${ID_DOMAIN} --json '{ "name": "*.'${HOSTNAME_EXTERNAL}'", "type": "CNAME", "content": "'${HOSTNAME_LB}'" }'
	fi
	/bin/rm ${FILE}
	echo "fix_load_balancer_hostname: FINISHED!"
}

function delete_wildcard_dns()
{	
	log_to_file /tmp/delete-wildcard-dns.log

	HOSTNAME_WILDCARD="apps.${CLUSTER_NAME}.scnl-ibm.com"
	ID_DOMAIN=$(ibmcloud cis domains --output json | jq -r '.[] | select (.name|test("^scnl-ibm.com$")) | .id')

	FOUND=false
	FILE=$(mktemp)

	while ! ${FOUND}
	do
		sleep 1m

		ibmcloud cis dns-records ${ID_DOMAIN} --output json > ${FILE}
		RC=$?
		if [ ${RC} -gt 0 ]
		then
			continue
		fi

		ibmcloud cis dns-records ${ID_DOMAIN} --output json | jq -r '.[] | select (.name|test("'${HOSTNAME_WILDCARD}'$"))' > ${FILE}
		RC=$?
		if [ ${RC} -eq 0 ]
		then
			LINE_OUTPUT=$(wc -l ${FILE})
			RC=$?
			if [ ${RC} -eq 0 ]
			then
				LINES=$(echo "${LINE_OUTPUT}" | cut -f1 -d' ')
				RC=$?
				if (( ${LINES} > 0 ))
				then
					FOUND=true
				fi
			fi
		fi

		if ${FOUND}
		then
			ID_WILDCARD=$(jq -r --slurp '.[0].id' ${FILE})
			ibmcloud cis dns-record-delete ${ID_DOMAIN} ${ID_WILDCARD}
		fi
	done

	/bin/rm ${FILE}
	echo "delete_wildcard_dns: FINISHED!"
}

function reboot_master_nodes()
{	
	log_to_file /tmp/reboot-master-nodes.log

	CLUSTER_ID=$(jq -r '.infraID' ${CLUSTER_DIR}/metadata.json)

	FOUND=false
	FILE=$(mktemp)

	while ! ${FOUND}
	do
		ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("^'${CLUSTER_ID}'-loadbalancer$"))' > ${FILE}
		RC=$?
		if [ ${RC} -eq 0 ]
		then
			LINE_OUTPUT=$(wc -l ${FILE})
			RC=$?
			if [ ${RC} -eq 0 ]
			then
				LINES=$(echo "${LINE_OUTPUT}" | cut -f1 -d' ')
				RC=$?
				if (( ${LINES} > 0 ))
				then
					FOUND=true
				fi
			fi
		else
			sleep 1m
		fi
	done

	LB_ID=$(ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("^'${CLUSTER_ID}'-loadbalancer$")) | .id')

	READY=false

	while ! ${READY}
	do
		STATUS=$(ibmcloud is load-balancers --json | jq -r '.[] | select (.id|test("'${LB_ID}'")) | .operating_status')
		if [ "${STATUS}" == "online" ]
		then
			READY=true
		fi
	done

	SELECT="${CLUSTER_ID}-master"
	W_FILE=$(mktemp)
	
	while true
	do
		ibmcloud pi ins --json | jq '.Payload.pvmInstances[] | select (.serverName|test("'${SELECT}'"))' > ${W_FILE}
	
		MASTER0=$(jq -r '. | select(.serverName|test("master-0")) | .addresses[].ip' ${W_FILE})
		MASTER1=$(jq -r '. | select(.serverName|test("master-1")) | .addresses[].ip' ${W_FILE})
		MASTER2=$(jq -r '. | select(.serverName|test("master-2")) | .addresses[].ip' ${W_FILE})

		if [ -n "${MASTER0}" ] && [ -n "${MASTER1}" ] && [ -n "${MASTER2}" ]
		then
			break
		fi

		sleep 1m
	done

	OUTPUT0=$(ssh cloud-user@161.156.204.62 ssh-keyscan ${MASTER0} || true)
	OUTPUT1=$(ssh cloud-user@161.156.204.62 ssh-keyscan ${MASTER1} || true)
	OUTPUT2=$(ssh cloud-user@161.156.204.62 ssh-keyscan ${MASTER2} || true)

	if [ -z "${OUTPUT0}" ]
	then
		echo ibmcloud pi instance-hard-reboot "${CLUSTER_ID}-master-0"
	fi

	if [ -z "${OUTPUT1}" ]
	then
		echo ibmcloud pi instance-hard-reboot "${CLUSTER_ID}-master-1"
	fi

	if [ -z "${OUTPUT2}" ]
	then
		echo ibmcloud pi instance-hard-reboot "${CLUSTER_ID}-master-2"
	fi

	/bin/rm ${FILE} ${W_FILE}
	echo "reboot_master_nodes: FINISHED!"
}

declare -a ENV_VARS
#ENV_VARS=( "CLUSTER_DIR" "CLUSTER_NAME" "IBMCLOUD_API_KEY" "IBMCLOUD_NETWORK" "IBMID" "POWERVS_REGION" "POWERVS_ZONE" "SERVICE_INSTANCE" "SUBNET" "VPC" "VPCREGION" )
ENV_VARS=( "CLUSTER_DIR" "CLUSTER_NAME" "IBMCLOUD_API_KEY" "IBMID" "POWERVS_REGION" "POWERVS_ZONE" "SERVICE_INSTANCE" "VPCREGION" )
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

#export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="quay.io/psundara/openshift-release:4.10-powervs"
#export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="quay.io/openshift-release-dev/ocp-release-nightly:4.11.0-0.nightly-ppc64le-2022-05-06-093203"
export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="quay.io/openshift-release-dev/ocp-release-nightly:4.11.0-0.nightly-ppc64le-2022-05-10-222820"

export PATH=${PATH}:$(pwd)/bin
export BASE64_API_KEY=$(echo -n ${IBMCLOUD_API_KEY} | base64)
export KUBECONFIG=${CLUSTER_DIR}/auth/kubeconfig
export IC_API_KEY=${IBMCLOUD_API_KEY}

#export TF_LOG_PROVIDER=TRACE
#export TF_LOG=TRACE
#export TF_LOG_PATH=/tmp/tf.log
#export IBMCLOUD_TRACE=true

set -x

# Quota check DNS
export DNS_DOMAIN_ID=$(ibmcloud cis domains --output json | jq -r '.[].id')
RECORDS=$(ibmcloud cis dns-records ${DNS_DOMAIN_ID} --output json | jq -r '.[] | select (.name|test("rdr-hamzy.*")) | "\(.name) - \(.id)"')
if [ -n "${RECORDS}" ]
then
	echo "${RECORDS}"
	exit 1
fi

# Quota check cloud connections
CONNECTIONS=$(ibmcloud pi connections --json | jq -r '.Payload.cloudConnections')
if [ "${CONNECTIONS}" != "[]" ]
then
	echo "${CONNECTIONS}"
	exit 1
fi

export SERVICE_INSTANCE_ID=$(ibmcloud resource service-instance ${SERVICE_INSTANCE} --output json | jq -r '.[].guid')

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

#platform:
#  powervs:
#    userid: "${IBMID}"
#    powervsResourceGroup: "powervs-ipi-resource-group"
#    pvsNetworkName: "${IBMCLOUD_NETWORK}"
#    region: "${POWERVS_REGION}"
#    vpcRegion: "${VPCREGION}"
#    zone: "${POWERVS_ZONE}"
#    serviceInstanceID: "${SERVICE_INSTANCE_ID}"
#    vpc: "${VPC}"
#    subnets:
#    - "${SUBNET}"

cat << ___EOF___ > ${CLUSTER_DIR}/install-config.yaml
apiVersion: v1
baseDomain: scnl-ibm.com
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
    powervsResourceGroup: "powervs-ipi-resource-group"
    region: "${POWERVS_REGION}"
    vpcRegion: "${VPCREGION}"
    zone: "${POWERVS_ZONE}"
    serviceInstanceID: "${SERVICE_INSTANCE_ID}"
publish: External
pullSecret: '${PULL_SECRET}'
sshKey: |
  ${SSH_KEY}
___EOF___

sed -i '/credentialsMode/d' ${CLUSTER_DIR}/install-config.yaml
sed -i '/^baseDomain:.*$/a credentialsMode: Manual' ${CLUSTER_DIR}/install-config.yaml

openshift-install create ignition-configs --dir ${CLUSTER_DIR} --log-level=debug

openshift-install create manifests --dir ${CLUSTER_DIR} --log-level=debug

cat << ___EOF___ > ${CLUSTER_DIR}/manifests/openshift-ccm-credentials.yaml
apiVersion: v1
kind: Secret
metadata:
  creationTimestamp: null
  name: ibm-cloud-credentials
  namespace: openshift-cloud-controller-manager
stringData:
  ibm-credentials.env: |-
    IBMCLOUD_AUTHTYPE=iam
    IBMCLOUD_APIKEY=${IBMCLOUD_API_KEY}
  ibmcloud_api_key: ${IBMCLOUD_API_KEY}
type: Opaque
___EOF___

if false
then

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
  IBMCLOUD_APIKEY=${IBMCLOUD_API_KEY}
 ibmcloud_api_key: ${IBMCLOUD_API_KEY}
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
  IBMCLOUD_APIKEY=${IBMCLOUD_API_KEY}
 ibmcloud_api_key: ${IBMCLOUD_API_KEY}
type: Opaque
___EOF___

else

cp ~/Downloads/openshift-cloud-controller-manager-ibm-cloud-credentials-credentials.yaml ${CLUSTER_DIR}/manifests/
cp ~/Downloads/openshift-ingress-operator-cloud-credentials-credentials.yaml ${CLUSTER_DIR}/manifests/

fi

if false
then
cp /home/OpenShift/git/karthik-cluster-cloud-controller-manager-operator/manifests/0000_26_cloud-controller-manager-operator_11_deployment.yaml ${CLUSTER_DIR}/manifests/
cp /home/OpenShift/git/karthik-cluster-cloud-controller-manager-operator/manifests/0000_26_cloud-controller-manager-operator_01_images.configmap.yaml ${CLUSTER_DIR}/manifests/
sed -i -e 's,image: .*$,image: quay.io/hamzy/cluster-cloud-controller-manager-operator:remove_port,' ${CLUSTER_DIR}/manifests/0000_26_cloud-controller-manager-operator_11_deployment.yaml
sed -i -e 's,quay.io/openshift/origin-cluster-cloud-controller-manager-operator,quay.io/hamzy/cluster-cloud-controller-manager-operator:remove_port,' ${CLUSTER_DIR}/manifests/0000_26_cloud-controller-manager-operator_01_images.configmap.yaml

# curl --silent --location --output - https://raw.githubusercontent.com/Karthik-K-N/cluster-cloud-controller-manager-operator/0d5cb9d8d46240724b71df602659b584268c89ab/pkg/cloud/powervs/assets/deployment.yaml | sed -e 's,{{ .cloudproviderName }},PowerVS,' -e 's,{{ .images.CloudControllerManager }},quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:daee38f9ba7e63d7e0a93c79d28a617edfde31523a107c68b3e01a8d63c7bfe1,' > ${CLUSTER_DIR}/manifests/

curl --silent --output - https://raw.githubusercontent.com/openshift/cluster-cloud-controller-manager-operator/release-4.11/manifests/0000_26_cloud-controller-manager-operator_15_credentialsrequest-powervs.yaml
fi

oc adm release extract --cloud=powervs --credentials-requests quay.io/openshift-release-dev/ocp-release:4.10.0-rc.2-ppc64le --to=${CLUSTER_DIR}/credreqs

openshift-install create cluster --dir ${CLUSTER_DIR} --log-level=debug &
PID_INSTALL=$!
JOBS+=( "${PID_INSTALL}" )

#create_ibm_cloud_credentials_secret &
#JOBS+=( "$!" )

#fix_load_balancer_hostname &
#JOBS+=( "$!" )

#delete_wildcard_dns &
#JOBS+=( "$!" )

wait ${PID_INSTALL}
