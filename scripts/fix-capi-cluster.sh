#!/usr/bin/env bash

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

function fix_security_group_rules()
{
	VPC=$(ibmcloud is vpcs --output json | jq -r '.[] | select (.name|test("'${CLUSTER_ID}'")) | .id')
	echo "VPC=${VPC}"
	[ -z "${VPC}" ] && echo "VPC is empty!" && exit 1

	SG_UUID=$(ibmcloud is vpc --output json ${VPC} | jq -r '.default_security_group.id')
	echo "SG_UUID=${SG_UUID}"
	[ -z "${SG_UUID}" ] && echo "SG_UUID is empty!" && exit 1

	ID=$(ibmcloud is security-group-rules ${SG_UUID} --json | jq -r '.[] | select(.port_min == 22) | .id')
	[ -z "${ID}" ] && ibmcloud is security-group-rule-add ${SG_UUID} inbound tcp --port-min 22 --port-max 22 --remote '0.0.0.0/0'
	ID=$(ibmcloud is security-group-rules ${SG_UUID} --json | jq -r '.[] | select(.port_min == 10258) | .id')
	[ -z "${ID}" ] && ibmcloud is security-group-rule-add ${SG_UUID} inbound tcp --port-min 10258 --port-max 10258 --remote '0.0.0.0/0'
	ID=$(ibmcloud is security-group-rules ${SG_UUID} --json | jq -r '.[] | select(.port_min == 22623) | .id')
	[ -z "${ID}" ] && ibmcloud is security-group-rule-add ${SG_UUID} inbound tcp --port-min 22623 --port-max 22623 --remote '0.0.0.0/0'
	ID=$(ibmcloud is security-group-rules ${SG_UUID} --json | jq -r '.[] | select(.protocol == "icmp") | .id')
	[ -z "${ID}" ] && ibmcloud is security-group-rule-add ${SG_UUID} inbound icmp --remote '0.0.0.0/0'

	return 0
}

function create_dns_entries()
{	
	#log_to_file /tmp/create-dns-entries.log

	HOSTNAME_EXTERNAL="api.${CLUSTER_NAME}.powervs-openshift-ipi.cis.ibm.net"
	HOSTNAME_INTERNAL="api-int.${CLUSTER_NAME}.powervs-openshift-ipi.cis.ibm.net"

	HOSTNAME_LB_EXT=$(ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("^'${CLUSTER_NAME}'.*-loadbalancer$")) | .hostname')
	[ -z "${HOSTNAME_LB_EXT}" ] && echo "HOSTNAME_LB_EXT is empty!" && exit 1

	HOSTNAME_LB_INT=$(ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("^'${CLUSTER_NAME}'.*-loadbalancer-int$")) | .hostname')
	[ -z "${HOSTNAME_LB_INT}" ] && echo "HOSTNAME_LB_INT is empty!" && exit 1

	ID_DOMAIN=$(ibmcloud cis domains --output json | jq -r '.[] | select (.name|test("^powervs-openshift-ipi.cis.ibm.net$")) | .id')

	echo "HOSTNAME_EXTERNAL=${HOSTNAME_EXTERNAL} HOSTNAME_LB_EXT=${HOSTNAME_LB_EXT}"
	ibmcloud cis dns-record-create ${ID_DOMAIN} --json '{ "name": "'${HOSTNAME_EXTERNAL}'", "type": "CNAME", "content": "'${HOSTNAME_LB_EXT}'", "ttl": 60 }'

	echo "HOSTNAME_INTERNAL=${HOSTNAME_INTERNAL} HOSTNAME_LB_INT=${HOSTNAME_LB_INT}"
	ibmcloud cis dns-record-create ${ID_DOMAIN} --json '{ "name": "'${HOSTNAME_INTERNAL}'", "type": "CNAME", "content": "'${HOSTNAME_LB_INT}'", "ttl": 60 }'

	echo "$(dig +short ${HOSTNAME_LB_INT} | head -n1) ${HOSTNAME_INTERNAL}" | sudo tee -a /etc/hosts
	echo "$(dig +short ${HOSTNAME_LB_EXT} | head -n1) ${HOSTNAME_EXTERNAL}" | sudo tee -a /etc/hosts

	return 0
}

function create_external_loadbalancer()
{
	VPC_ID=$(ibmcloud is vpcs --output json | jq -r '.[] | select (.name|test("'${CLUSTER_ID}'")) | .id')
	echo "VPC_ID=${VPC_ID}"
	[ -z "${VPC_ID}" ] && echo "VPC_ID is empty!" && exit 1

	ibmcloud is subnets --json | jq -r '.[] | select (.name|test("'${CLUSTER_ID}'"))' > ${FILE1}

	declare -a SUBNETS

	while read UUID
	do
		SUBNETS+=( ${UUID} )
	done <<< $(jq -r '.id' ${FILE1})
	echo "SUBNETS=${SUBNETS[*]}"
	echo "SUBNETS0=${SUBNETS[0]}"

	SG_ID=$(ibmcloud is security-groups --json | jq -r '.[] | select(.vpc.name|test("'${CLUSTER_ID}'")) | .id')
	echo "SG_ID=${SG_ID}"

	LB_EXT_ID=$(ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("'${CLUSTER_NAME}'.*-loadbalancer$")) | .id')
	if [ -z "${LB_EXT_ID}" ]
	then
		exit 1
		ibmcloud is load-balancer-create ${CLUSTER_ID}-loadbalancer public --subnet ${SUBNETS[0]} --subnet ${SUBNETS[1]} --subnet ${SUBNETS[2]} --vpc ${VPC_ID} --sg ${SG_ID}
		LB_EXT_ID=$(ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("rdr-hamzy.*--loadbalancer$")) | .id')
	fi

	wait_for_lb_ready ${LB_EXT_ID}

if false
then
	API_POOL_ID=$(ibmcloud is load-balancer ${LB_EXT_ID} --json | jq -r '.pools[] | select(.name|test("${CLUSTER_NAME}-loadbalancer-pool-6443")) | .id')
	if [ -z "${API_POOL_ID}" ]
	then
		ibmcloud is load-balancer-pool-create api-server ${LB_EXT_ID} round_robin tcp 60 5 30 tcp
		API_POOL_ID=$(ibmcloud is load-balancer ${LB_EXT_ID} --json | jq -r '.pools[] | select(.name|test("${CLUSTER_NAME}-loadbalancer-pool-6443")) | .id')
		wait_for_lb_ready ${LB_EXT_ID}
	fi

	ID=$(ibmcloud is load-balancer-pool-members ${LB_EXT_ID} ${API_POOL_ID} --json | jq -r '.[] | select(.target.address == "192.168.0.10") | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-pool-member-create ${LB_EXT_ID} ${API_POOL_ID} 6443 192.168.0.10
		wait_for_lb_ready ${LB_EXT_ID}
	fi

	ID=$(ibmcloud is load-balancer-pool-members ${LB_EXT_ID} ${API_POOL_ID} --json | jq -r '.[] | select(.target.address == "192.168.0.11") | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-pool-member-create ${LB_EXT_ID} ${API_POOL_ID} 6443 192.168.0.11
		wait_for_lb_ready ${LB_EXT_ID}
	fi

	ID=$(ibmcloud is load-balancer-pool-members ${LB_EXT_ID} ${API_POOL_ID} --json | jq -r '.[] | select(.target.address == "192.168.0.12") | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-pool-member-create ${LB_EXT_ID} ${API_POOL_ID} 6443 192.168.0.12
		wait_for_lb_ready ${LB_EXT_ID}
	fi

	ID=$(ibmcloud is load-balancer-pool-members ${LB_EXT_ID} ${API_POOL_ID} --json | jq -r '.[] | select(.target.address == "192.168.0.13") | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-pool-member-create ${LB_EXT_ID} ${API_POOL_ID} 6443 192.168.0.13
		wait_for_lb_ready ${LB_EXT_ID}
	fi

	ID=$(ibmcloud is load-balancer-listeners ${LB_EXT_ID} --output json | jq -r '.[] | select(.port == 6443) | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-listener-create ${LB_EXT_ID} --port 6443 --protocol tcp --default-pool ${API_POOL_ID}
		wait_for_lb_ready ${LB_EXT_ID}
	fi
fi

	return 0
}

function create_internal_loadbalancer()
{
	VPC_ID=$(ibmcloud is vpcs --output json | jq -r '.[] | select (.name|test("'${CLUSTER_ID}'")) | .id')
	echo "VPC_ID=${VPC_ID}"
	[ -z "${VPC_ID}" ] && echo "VPC_ID is empty!" && exit 1

	ibmcloud is subnets --json | jq -r '.[] | select (.name|test("'${CLUSTER_ID}'"))' > ${FILE1}

	declare -a SUBNETS

	while read UUID
	do
		SUBNETS+=( ${UUID} )
	done <<< $(jq -r '.id' ${FILE1})
	echo "SUBNETS=${SUBNETS[*]}"
	echo "SUBNETS0=${SUBNETS[0]}"

	SG_ID=$(ibmcloud is security-groups --json | jq -r '.[] | select(.vpc.name|test("'${CLUSTER_ID}'")) | .id')
	echo "SG_ID=${SG_ID}"

	LB_INT_ID=$(ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("'${CLUSTER_NAME}'.*-int")) | .id')
	if [ -z "${LB_INT_ID}" ]
	then
		ibmcloud is load-balancer-create ${CLUSTER_ID}-loadbalancer-int private --subnet ${SUBNETS[0]} --subnet ${SUBNETS[1]} --subnet ${SUBNETS[2]} --vpc ${VPC_ID} --sg ${SG_ID}
		LB_INT_ID=$(ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("rdr-hamzy.*-int")) | .id')
	fi

	wait_for_lb_ready ${LB_INT_ID}

	MCS_POOL_ID=$(ibmcloud is load-balancer ${LB_INT_ID} --json | jq -r '.pools[] | select(.name|test("machine-config-server")) | .id')
	if [ -z "${MCS_POOL_ID}" ]
	then
		ibmcloud is load-balancer-pool-create machine-config-server ${LB_INT_ID} round_robin tcp 60 5 30 tcp
		MCS_POOL_ID=$(ibmcloud is load-balancer ${LB_INT_ID} --json | jq -r '.pools[] | select(.name|test("machine-config-server")) | .id')
		wait_for_lb_ready ${LB_INT_ID}
	fi

	ID=$(ibmcloud is load-balancer-pool-members ${LB_INT_ID} ${MCS_POOL_ID} --json | jq -r '.[] | select(.target.address == "192.168.0.10") | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-pool-member-create ${LB_INT_ID} ${MCS_POOL_ID} 22623 192.168.0.10
		wait_for_lb_ready ${LB_INT_ID}
	fi

	ID=$(ibmcloud is load-balancer-pool-members ${LB_INT_ID} ${MCS_POOL_ID} --json | jq -r '.[] | select(.target.address == "192.168.0.11") | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-pool-member-create ${LB_INT_ID} ${MCS_POOL_ID} 22623 192.168.0.11
		wait_for_lb_ready ${LB_INT_ID}
	fi

	ID=$(ibmcloud is load-balancer-pool-members ${LB_INT_ID} ${MCS_POOL_ID} --json | jq -r '.[] | select(.target.address == "192.168.0.12") | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-pool-member-create ${LB_INT_ID} ${MCS_POOL_ID} 22623 192.168.0.12
		wait_for_lb_ready ${LB_INT_ID}
	fi

	ID=$(ibmcloud is load-balancer-pool-members ${LB_INT_ID} ${MCS_POOL_ID} --json | jq -r '.[] | select(.target.address == "192.168.0.13") | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-pool-member-create ${LB_INT_ID} ${MCS_POOL_ID} 22623 192.168.0.13
		wait_for_lb_ready ${LB_INT_ID}
	fi

	ID=$(ibmcloud is load-balancer-listeners ${LB_INT_ID} --output json | jq -r '.[] | select(.port == 22623) | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-listener-create ${LB_INT_ID} --port 22623 --protocol tcp --default-pool ${MCS_POOL_ID}
		wait_for_lb_ready ${LB_INT_ID}
	fi

	API_POOL_ID=$(ibmcloud is load-balancer ${LB_INT_ID} --json | jq -r '.pools[] | select(.name|test("api-server")) | .id')
	if [ -z "${API_POOL_ID}" ]
	then
		ibmcloud is load-balancer-pool-create api-server ${LB_INT_ID} round_robin tcp 60 5 30 tcp
		API_POOL_ID=$(ibmcloud is load-balancer ${LB_INT_ID} --json | jq -r '.pools[] | select(.name|test("api-server")) | .id')
		wait_for_lb_ready ${LB_INT_ID}
	fi

	ID=$(ibmcloud is load-balancer-pool-members ${LB_INT_ID} ${API_POOL_ID} --json | jq -r '.[] | select(.target.address == "192.168.0.10") | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-pool-member-create ${LB_INT_ID} ${API_POOL_ID} 6443 192.168.0.10
		wait_for_lb_ready ${LB_INT_ID}
	fi

	ID=$(ibmcloud is load-balancer-pool-members ${LB_INT_ID} ${API_POOL_ID} --json | jq -r '.[] | select(.target.address == "192.168.0.11") | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-pool-member-create ${LB_INT_ID} ${API_POOL_ID} 6443 192.168.0.11
		wait_for_lb_ready ${LB_INT_ID}
	fi

	ID=$(ibmcloud is load-balancer-pool-members ${LB_INT_ID} ${API_POOL_ID} --json | jq -r '.[] | select(.target.address == "192.168.0.12") | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-pool-member-create ${LB_INT_ID} ${API_POOL_ID} 6443 192.168.0.12
		wait_for_lb_ready ${LB_INT_ID}
	fi

	ID=$(ibmcloud is load-balancer-pool-members ${LB_INT_ID} ${API_POOL_ID} --json | jq -r '.[] | select(.target.address == "192.168.0.13") | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-pool-member-create ${LB_INT_ID} ${API_POOL_ID} 6443 192.168.0.13
		wait_for_lb_ready ${LB_INT_ID}
	fi

	ID=$(ibmcloud is load-balancer-listeners ${LB_INT_ID} --output json | jq -r '.[] | select(.port == 6443) | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-listener-create ${LB_INT_ID} --port 6443 --protocol tcp --default-pool ${API_POOL_ID}
		wait_for_lb_ready ${LB_INT_ID}
	fi

	return 0
}

function wait_for_lb_ready()
{
	LB_ID=$1
	[ -z "${LB_ID}" ] && echo "LB_ID is empty!" && exit 1

	STATUS=$(ibmcloud is load-balancer ${LB_ID} --json | jq -r '.operating_status')
	while [ "${STATUS}" != "online" ]
	do
		sleep 5s
		STATUS=$(ibmcloud is load-balancer ${LB_ID} --json | jq -r '.operating_status')
	done

	STATUS=$(ibmcloud is load-balancer ${LB_ID} --json | jq -r '.provisioning_status')
	while [ "${STATUS}" != "active" ]
	do
		sleep 5s
		STATUS=$(ibmcloud is load-balancer ${LB_ID} --json | jq -r '.provisioning_status')
	done

	return 0
}

function add_ssh_server_pool()
{
	LB_EXT_ID=$(ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("'${CLUSTER_ID}'-loadbalancer$")) | .id')
	[ -z "${LB_EXT_ID}" ] && echo "LB_EXT_ID is empty!" && exit 1

	wait_for_lb_ready ${LB_EXT_ID}

	SSH_POOL_ID=$(ibmcloud is load-balancer ${LB_EXT_ID} --json | jq -r '.pools[] | select(.name|test("ssh-server")) | .id')
	if [ -z "${SSH_POOL_ID}" ]
	then
		ibmcloud is load-balancer-pool-create ssh-server ${LB_EXT_ID} round_robin tcp 60 5 30 tcp
		SSH_POOL_ID=$(ibmcloud is load-balancer ${LB_EXT_ID} --json | jq -r '.pools[] | select(.name|test("ssh-server")) | .id')
		wait_for_lb_ready ${LB_EXT_ID}
	fi

	ID=$(ibmcloud is load-balancer-pool-members ${LB_EXT_ID} ${SSH_POOL_ID} --json | jq -r '.[] | select(.target.address == "192.168.0.12") | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-pool-member-create ${LB_EXT_ID} ${SSH_POOL_ID} 22 192.168.0.12
		wait_for_lb_ready ${LB_EXT_ID}
	fi

	ID=$(ibmcloud is load-balancer-listeners ${LB_INT_ID} --output json | jq -r '.[] | select(.port == 22) | .id')
	if [ -z "${ID}" ]
	then
		ibmcloud is load-balancer-listener-create ${LB_EXT_ID} --port 22 --protocol tcp --default-pool ${SSH_POOL_ID}
		wait_for_lb_ready ${LB_EXT_ID}
	fi

	return 0
}

function add_worker_ssh_key()
{
	ID=$(ibmcloud pi ssh-key list 2>/dev/null | grep "${CLUSTER_ID}-key" || true)
	if [ -z "${ID}" ]
	then
		ibmcloud pi ssh-key create "${CLUSTER_ID}-key" --key "$(cat ~/.ssh/id_installer_rsa.pub)"
	fi

	return 0
}

declare -a ENV_VARS
ENV_VARS=( "IBMCLOUD_API_KEY" "CLUSTER_DIR" )

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

export PATH=${PATH}:$(pwd)/bin
export BASE64_API_KEY=$(echo -n ${IBMCLOUD_API_KEY} | base64)
export KUBECONFIG=${CLUSTER_DIR}/auth/kubeconfig
export IC_API_KEY=${IBMCLOUD_API_KEY}

set -x

CLUSTER_NAME=$(jq -r '.clusterName' ${CLUSTER_DIR}/metadata.json)
[ -z "${CLUSTER_NAME}" ] && echo "CLUSTER_NAME is empty!" && exit 1

CLUSTER_ID=$(jq -r '.infraID' ${CLUSTER_DIR}/metadata.json)
[ -z "${CLUSTER_ID}" ] && echo "CLUSTER_ID is empty!" && exit 1

if [ -z "${VPCREGION}" ]
then
	VPCREGION=$(jq -r '.powervs.vpcRegion' ${CLUSTER_DIR}/metadata.json)
fi
[ -z "${VPCREGION}" ] && echo "VPCREGION is empty!" && exit 1

init_ibmcloud

FILE1=$(mktemp)
trap "/bin/rm -rf ${FILE1}" EXIT

#fix_security_group_rules

#create_external_loadbalancer

#create_internal_loadbalancer

#add_ssh_server_pool

#add_worker_ssh_key

#create_dns_entries
