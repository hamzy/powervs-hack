#!/bin/bash
set -euo pipefail

INITIALIZE=/bin/false
CREATE=/bin/true
DESTROY=/bin/false

if [ $# -eq 1 ]
then
	CREATE=/bin/false
	DESTROY=/bin/true
fi

cd test-terraform-rhcos || exit 1
pwd

export PATH=${PATH}:../terraform/bin/linux_amd64/
echo ${PATH}

hash terraform || exit 1

if ${INITIALIZE}
then
	if ${CREATE}
	then
	(
		set -xe
		export NAME="rdr-hamzy-rhcos-syd04"
		export VPC1_NAME="${NAME}-vpc"
		ibmcloud is vpc-create ${VPC1_NAME} --resource-group-name powervs-ipi-resource-group
		VPC1_CRN=$(ibmcloud is vpcs --output json | jq -r '.[] | select (.name|test("'${VPC1_NAME}'")) | .crn')
		echo "${VPC1_CRN}"
		export CC_NAME="${NAME}-cc"
		ibmcloud pi connection-create ${CC_NAME} --speed 1000 --vpc --vpcID ${VPC1_CRN}
	)
	fi
fi

if ${CREATE}
then
	/bin/rm -rf .terraform* terraform.* test-terraform-rhcos.out

	terraform init
fi

export TF_VAR_ibmcloud_api_key=${IBMCLOUD_API_KEY}
export TF_VAR_ibmcloud_region="syd"
export TF_VAR_ibmcloud_zone="syd04"
export TF_VAR_resource_group="powervs-ipi-resource-group"
export TF_VAR_cluster_id="rdr-hamzy-$(hexdump -vn4 -e'4/4 "%08X" 1 "\n"' /dev/urandom | tr -d ' ' | tr '[:upper:]' '[:lower:]')-rhcos"
export TF_VAR_cos_instance_location="global"
export TF_VAR_cos_bucket_location="au-syd"
export TF_VAR_cos_storage_class="smart"
export TF_VAR_cos_region="au-syd"
export TF_VAR_image_bucket_name="rhcos-powervs-images-au-syd"
export TF_VAR_image_bucket_file_name="rhcos-413-86-202212131234-0-ppc64le-powervs.ova.gz"
#export TF_VAR_image_storage_type="tier1"
export TF_VAR_cloud_connection_id="03cb63e3-a449-4953-bbcb-5efdfbae6207"
export TF_VAR_service_instance_id="1e6e901c-09e5-4a47-bed5-830e6629442d"
export TF_VAR_network_id="1cc430d3-9ca3-41a5-8e8b-77f2bf42a685"
export TF_VAR_pub_key=$(cat ~/.ssh/id_rsa.pub)

if ${CREATE}
then
	terraform plan -out test-terraform-rhcos.out

	date --utc +%Y-%m-%dT%H:%M:%S%:z

	terraform apply "test-terraform-rhcos.out"
fi

if ${DESTROY}
then
	if /bin/false
	then
		export TF_VAR_cluster_id="rdr-hamzy-$1-rhcos"

		terraform destroy
	else
		(while read ID; do ibmcloud pi instance-delete ${ID}; done) < <(ibmcloud pi instances --json | jq -r '.pvmInstances[] | select(.serverName|test("hamzy.*-rhcos-vm")) | .pvmInstanceID')
		(while read ID; do ibmcloud resource service-instance-delete --force --recursive ${ID}; done) < <(ibmcloud resource service-instances --all-resource-groups --output json | jq -r '.[] | select(.name|test("hamzy.*-rhcos-cos")) | .id')
		(while read ID; do ibmcloud pi image-delete ${ID}; done) < <(ibmcloud pi images --json | jq -r '.images[] | select(.name|test("hamzy.*-rhcos")) | .imageID')
	fi

	if ${INITIALIZE}
	then
	(
		export NAME="rdr-hamzy-rhcos-syd04"
		export VPC1_NAME="${NAME}-vpc"
		export CC_NAME="${NAME}-cc"
		ID=$(ibmcloud pi connections --json | jq -r '.Payload.cloudConnections[] | select (.name|test("'${CC_NAME}'")) | .cloudConnectionID')
		[ -z "${ID}" ] && exit 1
		JOBID=$(ibmcloud pi connection-delete ${ID} --json | jq -r '.id')
		while true
		do
			STATE=$(ibmcloud pi job ${JOBID} --json | jq -r '.status.state')
	       		echo "${STATE}"
       			if [ "${STATE}" == "completed" ]
			then
				break
	       		fi
       			sleep 1m
		done
		ibmcloud is vpc-delete ${VPC1_NAME} --force
	)
	fi
fi
