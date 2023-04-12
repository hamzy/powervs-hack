#!/usr/bin/env python3

# Running this program:
# $ python3 -m venv venv
# $ source venv/bin/activate
# $ pip install --upgrade pip
# $ pip install --requirement requirements.txt
#
# (venv) JobHistory2$ ./JobHistory.py https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs
#
# (venv) JobHistory2$ ./JobHistory.py https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-serial-ovn-ppc64le-powervs


# 0.1 on 2020-06-14
# 0.2 on 2023-04-10
# 0.3 on 2023-04-11
# 0.3.1 on 2023-04-12
# 0.4 on 2023-04-12
__version__ = "0.4"
__date__ = "2023-04-12"
__author__ = "Mark Hamzy (mhamzy@redhat.com)"

import argparse
from bs4 import BeautifulSoup
from datetime import datetime
import gzip
import http.cookiejar
import io
import json
import pdb
import re
import sys
import urllib.request
import zlib

num_deploys = 0
deploys_succeeded = 0
green_runs = 0

def get_url_string(url):
    url_response = opener.open(url)
    url_data = get_data(url_response)
    return url_data.decode()

def get_data(response):
    data_ret = None
    if response.info().get('Content-Encoding') in ['gzip', 'x-gzip']:
        buf = io.BytesIO(response.read())
        fileobj = gzip.GzipFile(fileobj=buf)
        data_ret = fileobj.read()
    elif response.info().get('Content-Encoding') == 'deflate':
        buf = io.BytesIO(response.read())
        try:
            fileobj = io.BytesIO(zlib.decompress(buf))
        except zlib.error:
            fileobj = io.BytesIO(zlib.decompressobj(-zlib.MAX_WBITS).decompress(buf))
        data_ret = fileobj.read()
    elif response.info().get('Content-Encoding') is None:
        data_ret = response.read()
    else:
        print("Error: Unknown response!")
        sys.exit(1)

    return data_ret

def run_match (tag):
    if tag.name != "tr":
        return False
    if not tag.has_attr("class"):
        return False
    if tag["class"][0] == "run-failure":
        return True
    return tag["class"][0] == "run-success"

def include_with_date (after_dt, before_dt, spyglass_link, ci_type_str):
    started_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/started.json"
    started_str = get_url_string(started_url)
    started_json = json.loads(started_str)
    started_dt = datetime.utcfromtimestamp(int(started_json['timestamp']))
    # print(started_json['timestamp'])
    # print("started_dt = " + started_dt.isoformat())
    # print("started_dt >= after_dt = " + str(started_dt >= after_dt))
    # print("started_dt <= before_dt = " + str(started_dt <= before_dt))

    print("Started on %s" % (started_dt, ))
    if (started_dt >= after_dt) and (started_dt <= before_dt):
        return True
    else:
        return False

def print_test_run_1 (spyglass_link, ci_type_str):
    test_log_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/openshift-e2e-libvirt-test/artifacts/e2e.log"
    test_log_str = get_url_string(test_log_url)

    if test_log_str.find('<!doctype html>') == -1:
        print(test_log_url)

        flaky_tests_re = re.compile('(.*)(Flaky tests:\n)(.*)', re.MULTILINE|re.DOTALL)
        flaky_tests_match = flaky_tests_re.match(test_log_str)
        if flaky_tests_match is not None:
            print(flaky_tests_match.group(3))
        else:
            failing_tests_re = re.compile('(.*)(Failing tests:\n)(.*)', re.MULTILINE|re.DOTALL)
            failing_tests_match = failing_tests_re.match(test_log_str)

            if failing_tests_match is not None:
                print(failing_tests_match.group(3))
            else:
                print("Error: Test log not matching anything?")
                # pdb.set_trace()

def print_test_run_2 (spyglass_link, ci_type_str):
    global green_runs

    test_log_junit_dir_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/openshift-e2e-libvirt-test/artifacts/junit/"
    test_log_junit_dir_str = get_url_string(test_log_junit_dir_url)

    test_failure_summary_filename_str = None
    test_failure_summary_filename_re = re.compile('(test-failures-summary_[^.]*\.json)')
    test_failure_summary_filename_match = test_failure_summary_filename_re.search(test_log_junit_dir_str, re.MULTILINE|re.DOTALL)
    if test_failure_summary_filename_match is not None:
        test_failure_summary_filename_str = test_failure_summary_filename_match.group(1)
    else:
        print("Error: Could not find test-failures-summary_*.json?")
        print("")
        return

    test_log_junit_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/openshift-e2e-libvirt-test/artifacts/junit/" + test_failure_summary_filename_str
    test_log_junit_str = get_url_string(test_log_junit_url)

    test_log_junit_json = json.loads(test_log_junit_str)

    tests = test_log_junit_json['Tests']
    if tests == []:
        print("SUCCESS: All tests succeeded!")

        green_runs += 1
    else:
        print("FAILURE: Failing tests:")
        for test in tests:
            print(test['Test']['Name'])

    print("")

    # pdb.set_trace()

def fromisoformat (date_str):
    # Argh! New in version 3.7: datetime.fromisoformat :(
    # dt = datetime.fromisoformat(date_str)

    # https://en.wikipedia.org/wiki/ISO_8601
    recognized_formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d"
    ]

    dt = None
    for date_format in recognized_formats:
        try:
            dt = datetime.strptime(date_str, date_format)
        except ValueError as e:
            pass
        if dt is not None:
            return dt

    return dt

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Extract CI runs')
    parser.add_argument('-a', '--after-date',
                        type=str,
                        dest='after_str',
                        nargs=1,
                        help='Only queries after this date')
    parser.add_argument('-b', '--before-date',
                        type=str,
                        dest='before_str',
                        nargs=1,
                        help='Only queries before this date')
    parser.add_argument('-u', '--url',
                        type=str,
                        required=True,
                        dest='url',
                        nargs=1,
                        help='URL of the CI to use')

    args = parser.parse_args()

    if len(args.url) != 1:
        print("Error: Expecting exactly one URL")
        print("Usage: ./JobHistory.py https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-serial-ovn-ppc64le-powervs")
        sys.exit(1)

    url = args.url[0]
    idx = url.find('https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/')
    if idx == -1:
        print("Error: unknown CI URL")
        exit(1)

    after_str = datetime.min.isoformat()
    if args.after_str is not None:
        after_str = args.after_str[0]
    # print("after_str = " + after_str)
    after_dt = fromisoformat(after_str)
    # print("after_dt = %s" % (after_dt, ))
    if after_dt is None:
        print("Error: unknown formatted date %s" % (after_str, ))
        sys.exit(1)

    before_str = datetime.today().isoformat()
    if args.before_str is not None:
        before_str = args.before_str[0]
    # print("before_str = " + before_str)
    before_dt = fromisoformat(before_str)
    # print("before_dt = %s" % (before_dt, ))
    if before_dt is None:
        print("Error: unknown formatted date %s" % (before_str, ))
        sys.exit(1)

    print("Finding CI runs between %s and %s" % (after_str, before_dt, ))

    # Ex:
    # url:
    #   https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs
    # ci_str:
    #   periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs
    # ci_version_str:
    #   4.13
    # ci_type_str:
    #   ocp-e2e-ovn-ppc64le-powervs
    idx = url.rfind('/')
    ci_str = url[idx+1:]
    ci_info_re = re.compile('([^0-9].*)-([0-9]\.[0-9]*)-(.*)')
    ci_info_match = ci_info_re.match(ci_str)
    if ci_info_match is None:
        print("Error: ci_info_re didn't match?")
        exit(1)
    ci_version_str = ci_info_match.group(2)
    ci_type_str = ci_info_match.group(3)

    cj = http.cookiejar.CookieJar()

    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler(),
                                         urllib.request.HTTPHandler(debuglevel=0),
                                         urllib.request.HTTPSHandler(debuglevel=0),
                                         urllib.request.HTTPCookieProcessor(cj))

    root_response = opener.open(url)
    root_data = get_data(root_response)

    root_soup = BeautifulSoup(root_data, features = "html.parser")

    for script_bs in root_soup.findAll('script'):
        script_str = script_bs.text
        idx = script_str.find('var allBuilds')
        if idx == -1:
            continue
        table_match = re.search('(var allBuilds = )(\[[^]]+\])(;)', script_str)
        table_str = table_match.group(2)
        table_map = json.loads(table_str)
        for spyglass_link in table_map:

            if not include_with_date (after_dt, before_dt, spyglass_link, ci_type_str):
                continue

            num_deploys += 1

            print('8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------')

            # Ex:
            # {'SpyglassLink': '/view/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.12-ocp-e2e-ovn-ppc64le-powervs/1620753919086956544', 'ID': '1620753919086956544', 'Started': '2023-02-01T12:00:25Z', 'Duration': 12390000000000, 'Result': 'FAILURE', 'Refs': None}
            # 
            # print(spyglass_link['SpyglassLink'])

            # https://prow.ci.openshift.org
            # job_url:
            #   https://prow.ci.openshift.org/view/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs/1645426556757086208
            # build_log_url:
            #   https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs/1645426556757086208/artifacts/ocp-e2e-ovn-ppc64le-powervs/ipi-install-powervs-install/build-log.txt
            #
            job_url = "https://prow.ci.openshift.org" + spyglass_link['SpyglassLink']
            print(job_url)

            # job_response = opener.open(job_url)
            # job_data = get_data(job_response)
            # job_soup = BeautifulSoup(job_data, features = "html.parser")

            build_log_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/ipi-install-powervs-install/build-log.txt"
            # print(build_log_url)

            build_finished_str = get_url_string("https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/ipi-install-powervs-install/finished.json")
            if build_finished_str.find('<!doctype html>') == -1:
                build_finished_json = json.loads(build_finished_str)
            else:
                build_finished_json = {'result': 'FAILURE'}

            build_log_response = opener.open(build_log_url)
            build_log_data = get_data(build_log_response)
            # build_log_soup = BeautifulSoup(build_log_data, features = "html.parser")

            build_log_str = build_log_data.decode()
            create_cluster_re = re.compile('(.*)(8<--------8<--------8<--------8<-------- BEGIN: create cluster 8<--------8<--------8<--------8<--------\n)(.*)(8<--------8<--------8<--------8<-------- END: create cluster 8<--------8<--------8<--------8<--------\n)(.*)', re.MULTILINE|re.DOTALL)
            create_cluster_match = create_cluster_re.match(build_log_str)

            if build_finished_json['result'] == 'SUCCESS':
                print("SUCCESS: create cluster succeeded!")

                deploys_succeeded += 1

                print_test_run_2(spyglass_link, ci_type_str)
            else:
                if create_cluster_match is not None:
                    print(create_cluster_match.group(3))
                else:
                    print("FAILURE: Could not find create cluster?")
                    print("")

            # pdb.set_trace()

        print("finished")
        print("%d/%d deploys succeeded" % (deploys_succeeded, num_deploys, ))
        print("%d/%d e2e green runs" % (green_runs, num_deploys, ))
