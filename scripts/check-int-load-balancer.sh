#!/usr/bin/env bash

set -euo pipefail

LB_INT_FILE=$(mktemp)
LB_MCS_POOL_FILE=$(mktemp)

trap "/bin/rm ${LB_INT_FILE} ${LB_MCS_POOL_FILE}" EXIT

INFRA_ID=$(jq -r '.infraID' ./ocp-test-syd04/metadata.json)

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
