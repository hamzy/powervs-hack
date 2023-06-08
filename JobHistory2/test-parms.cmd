#!/usr/bin/env bash

SOURCE=${BASH_SOURCE[0]}
while [ -L "${SOURCE}" ]; do # resolve ${SOURCE} until the file is no longer a symlink
  TARGET=$(readlink "${SOURCE}")
  if [[ ${TARGET} == /* ]]; then
    #echo "SOURCE '${SOURCE}' is an absolute symlink to '${TARGET}'"
    SOURCE=${TARGET}
  else
    DIR=$( dirname "${SOURCE}" )
    #echo "SOURCE '${SOURCE}' is a relative symlink to '${TARGET}' (relative to '${DIR}')"
    SOURCE=${DIR}/${TARGET} # if ${SOURCE} was a relative symlink, we need to resolve it relative to the path where the symlink file was located
  fi
done
#echo "SOURCE is '${SOURCE}'"
RDIR=$( dirname "${SOURCE}" )
DIR=$( cd -P "$( dirname "${SOURCE}" )" >/dev/null 2>&1 && pwd )
if [ "${DIR}" != "${RDIR}" ]; then
  #echo "DIR '${RDIR}' resolves to '${DIR}'"
  :
fi
#echo "DIR is '${DIR}'"

source ${DIR}/venv/bin/activate

if ! ${DIR}/JobHistory.py --version
then
  echo "JobHistory.py --version"
  exit 1
fi

if ! ${DIR}/JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs
then
  echo "JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs"
  exit 1
fi

if ! ${DIR}/JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs --today
then
  echo "JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs --today"
  exit 1
fi

if ! ${DIR}/JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs --yesterday
then
  echo "JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs --yesterday"
  exit 1
fi

if ! ${DIR}/JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs --last-n-days 1
then
  echo "JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs --last-n-days 1"
  exit 1
fi

if ! ${DIR}/JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs --last-n-days 1 --output /tmp/test-parms.out
then
  echo "JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs --last-n-days 3 --output /tmp/test-parms.out"
  exit 1
fi

if ! ${DIR}/JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.14-ocp-e2e-ovn-ppc64le-powervs --zone tok04
then
  echo "JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.14-ocp-e2e-ovn-ppc64le-powervs --zone tok04"
  exit 1
fi

if ! ${DIR}/JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs --after-date '2023-04-28T00:00:00Z'
then
  echo "JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs --after-date '2023-04-28T00:00:00Z'"
  exit 1
fi

if ! ${DIR}/JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs --after-date '2023-04-06T00:00:00Z' --before '2023-04-11T00:00:00Z'
then
  echo "JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs --after-date '2023-04-06T00:00:00Z' --before '2023-04-11T00:00:00Z'"
  exit 1
fi

if ! ${DIR}/JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs --after-date '2023-04-06T00:00:00Z' --csv --output /tmp/test-parm.csv
then
  echo "JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs --after-date '2023-04-06T00:00:00Z' --csv --output /tmp/test-parm.csv"
  exit 1
fi

if ! ${DIR}/JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.14-ocp-e2e-ovn-ppc64le-powervs --today --output /tmp/test-parm.csv
then
  echo "JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.14-ocp-e2e-ovn-ppc64le-powervs --today --output /tmp/test-parm.csv"
  exit 1
fi
