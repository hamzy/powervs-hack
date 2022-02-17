#!/usr/bin/env bash

set -xe

if [ -z "${IBMCLOUD_API_KEY}" ]
then
	echo "Error: IBMCLOUD_API_KEY must be set!"
	exit 1
fi

export PATH=${PATH}:$(pwd)/bin
export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE="quay.io/psundara/openshift-release:4.10-powervs"
export IBMID="hamzy@us.ibm.com"
export IBMCLOUD_REGION="lon"
export IBMCLOUD_ZONE="lon04"
export BASE64_API_KEY=$(echo -n ${IBMCLOUD_API_KEY} | base64)

rm -rf ocp-test/
mkdir ocp-test
cp install-config.yaml ocp-test/

openshift-install create ignition-configs --dir ocp-test --log-level=debug

openshift-install create manifests --dir ocp-test --log-level=debug

cat << ___EOF___ > ocp-test/manifests/openshift-ingress-operator-cloud-credentials-credentials.yaml
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

cat << ___EOF___ > ocp-test/manifests/openshift-machine-api-powervs-credentials-credentials.yaml
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

curl --silent --output - https://raw.githubusercontent.com/openshift/cluster-cloud-controller-manager-operator/release-4.11/manifests/0000_26_cloud-controller-manager-operator_15_credentialsrequest-powervs.yaml

oc adm release extract --cloud=powervs --credentials-requests quay.io/openshift-release-dev/ocp-release:4.10.0-rc.2-ppc64le --to=ocp-test/credreqs

openshift-install create cluster --dir ocp-test --log-level=debug
