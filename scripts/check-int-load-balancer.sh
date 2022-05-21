#!/usr/bin/env bash

declare -a ENV_VARS
ENV_VARS=( "CLUSTER_DIR" "IBMCLOUD_API_KEY" )

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

LB_INT_FILE=$(mktemp)
LB_MCS_POOL_FILE=$(mktemp)

trap "/bin/rm ${LB_INT_FILE} ${LB_MCS_POOL_FILE}" EXIT

INFRA_ID=$(jq -r '.infraID' ${CLUSTER_DIR}/metadata.json)

ibmcloud is load-balancers --output json | jq -r '.[] | select (.name|test("'${INFRA_ID}'-loadbalancer-int"))' > ${LB_INT_FILE}

LB_INT_ID=$(jq -r .id ${LB_INT_FILE})
echo "LB_INT_ID=${LB_INT_ID}";

LB_MCS_ID=$(jq -r '.pools[] | select (.name|test("machine-config-server")) | .id' ${LB_INT_FILE})
echo "LB_MCS_ID=${LB_MCS_ID}"

ibmcloud is load-balancer-pool ${LB_INT_ID} ${LB_MCS_ID} --output json > ${LB_MCS_POOL_FILE}

(
	while read LB_MEMBER_ID
	do
		echo ibmcloud is load-balancer-pool-member ${LB_INT_ID} ${LB_MCS_ID} ${LB_MEMBER_ID}
		ibmcloud is load-balancer-pool-member ${LB_INT_ID} ${LB_MCS_ID} ${LB_MEMBER_ID}
	done
) < <(jq -r '.members[] | .id' ${LB_MCS_POOL_FILE})
