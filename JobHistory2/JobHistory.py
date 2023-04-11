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
__version__ = "0.3"
__date__ = "2023-04-11"
__author__ = "Mark Hamzy (mhamzy@redhat.com)"

import argparse
from bs4 import BeautifulSoup
import gzip
import http.cookiejar
import io
import json
import pdb
import re
import sys
import urllib.request
import zlib

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

def print_test_run_1 (spyglass_link, ci_type_str):
    test_log_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/openshift-e2e-libvirt-test/artifacts/e2e.log"
    test_log_str = get_url_string(test_log_url)

    if test_log_str.find('<!doctype html>') == -1:
        print("test cluster succeeded!")
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
                print("Test log not matching anything?")
                # pdb.set_trace()

def print_test_run_2 (spyglass_link, ci_type_str):
    test_log_junit_dir_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/openshift-e2e-libvirt-test/artifacts/junit/"
    test_log_junit_dir_str = get_url_string(test_log_junit_dir_url)

    test_failure_summary_filename_str = None
    test_failure_summary_filename_re = re.compile('(test-failures-summary_[^.]*\.json)')
    test_failure_summary_filename_match = test_failure_summary_filename_re.search(test_log_junit_dir_str, re.MULTILINE|re.DOTALL)
    if test_failure_summary_filename_match is not None:
        test_failure_summary_filename_str = test_failure_summary_filename_match.group(1)
    else:
        print("Error: Could not file test-failures-summary_*.json?")
        print("")
        return

    test_log_junit_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/openshift-e2e-libvirt-test/artifacts/junit/" + test_failure_summary_filename_str
    test_log_junit_str = get_url_string(test_log_junit_url)

    test_log_junit_json = json.loads(test_log_junit_str)

    tests = test_log_junit_json['Tests']
    if tests == []:
        print("All tests succeeded!")
    else:
        print("Failing tests:")
        for test in tests:
            print(test['Test']['Name'])

    print("")

    # pdb.set_trace()

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('url', type=str, nargs=1)

    args = parser.parse_args()

    if len(args.url) != 1:
        print("Error: Expecting exactly one URL")
        print("Usage: ./JobHistory.py https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-serial-ovn-ppc64le-powervs")
        sys.exit(1)

    url = args.url[0]
    idx = url.find('https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/')
    if idx == -1:
        print("Error: unknown URL")
        exit(1)

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
            print(build_log_url)

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
                print("create cluster succeeded!")

                print_test_run_2(spyglass_link, ci_type_str)
            else:
                if create_cluster_match is not None:
                    print(create_cluster_match.group(3))
                else:
                    print("Could not find create cluster?")
                    print("")

            # pdb.set_trace()

        print("finished")
