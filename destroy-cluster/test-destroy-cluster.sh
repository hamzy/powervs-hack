# Copyright 2021 IBM Corp
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/usr/bin/env bash
set -o errexit
set -o xtrace

# ibmcloud resource service-instances --output json --service-name cloud-object-storage
# ibmcloud is security-groups --json | jq -r '.[] | select (.name|test("rdr-hamzy.*")) | [ .name, .id ]'
# ibmcloud is lbs --output json
# ibmcloud pi service-list --json | jq -r '.[] | select (.Name|test("powervs-ipi-lon04")) | .CRN'
# ibmcloud pi st crn:v1:bluemix:public:power-iaas:lon04:a/65b64c1f1c29460e8c2e4bbfbd893c2c:e449d86e-c3a0-4c07-959e-8557fdf55482::
# ibmcloud pi ins --json
# ibmcloud sl dns record-list scnl-ibm.com --output json
# ibmcloud cis instance-set powervs-ipi-cis; ibmcloud cis domains --output json
# ibmcloud cis dns-records 3e4c8a33b7373f077a1e50677d277b1f --output json

(
while read ID
do
	ibmcloud is load-balancer-delete --force ${ID}

	RESULT="x"
	while [ -n "${RESULT}" ]
	do
		RESULT=$(ibmcloud is load-balancers --json | jq -r '.[] | select (.id == "'${ID}'") | "\(.operating_status),\(.provisioning_status)"')
		sleep 15s
	done
done
) < <(ibmcloud is load-balancers --json | jq -r '.[] | select (.name|test("rdr-hamzy*")) | .id')

(
while read ID
do
	ibmcloud resource service-instance-delete "${ID}" --force --recursive
done
) < <(ibmcloud resource service-instances --service-name cloud-object-storage --output json | jq -r '.[] | select (.name|test("rdr-hamzy-test.*")) | .id')

(
while read ID
do
	ibmcloud is security-group-delete --force ${ID}
done
) < <(ibmcloud is security-groups --json | jq -r '.[] | select (.name|test("rdr-hamzy.*")) | .id')

SERVICE_ID=$(ibmcloud pi service-list --json | jq -r '.[] | select (.Name|test("powervs-ipi-lon04")) | .CRN')
ibmcloud pi service-target ${SERVICE_ID}

(
while read ID
do
	ibmcloud pi instance-delete --delete-data-volumes ${ID}

#	RESULT="x"
#	while [ -n "${RESULT}" ]
#	do
		INS_JSON=$(ibmcloud pi instance ${ID} --json)
		echo ${INS_JSON} > bob.json
#		RESULT=$(echo "${INS_JSON}" | jq -r '.status')
#		sleep 15s
#	done
done
) < <(ibmcloud pi instances --json | jq -r '.Payload.pvmInstances[] | select (.serverName|test("rdr-hamzy.*")) | .pvmInstanceID')

ibmcloud cis instance-set powervs-ipi-cis
DNS_DOMAIN_ID=$(ibmcloud cis domains --output json | jq -r '.[].id')

(
while read ID
do
	ibmcloud cis dns-record-delete ${DNS_DOMAIN_ID} ${ID}
done
) < <(ibmcloud cis dns-records ${DNS_DOMAIN_ID} --output JSON | jq -r '.[] | select (.name|test(".*rdr-hamzy.*")) | .id')
