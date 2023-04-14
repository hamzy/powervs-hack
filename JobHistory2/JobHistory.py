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
# 0.5 on 2023-04-13
# 0.6 on 2023-04-13
# 0.7 on 2023-04-14
__version__ = "0.7"
__date__ = "2023-04-14"
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

output_fp = sys.stdout
info_fp = sys.stderr

num_deploys = 0
deploys_succeeded = 0
green_runs = 0

def get_url_string(url):
    url_response = opener.open(url)
    url_data = get_data(url_response)
    return url_data.decode()

def get_data(response):
    global output_fp
    global info_fp

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
        info_fp.write("ERROR: Unknown response!\n")
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

def include_with_zone (zone, spyglass_link, ci_type_str):
    global output_fp
    global info_fp

    zone_log_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/build-log.txt"
    zone_log_str = get_url_string(zone_log_url)
    zone_log_re = re.compile('(Acquired 1 lease\(s\) for powervs-1-quota-slice: \[)([^]]+)(\])', re.MULTILINE|re.DOTALL)
    zone_log_match = zone_log_re.search(zone_log_str)

    if zone is not None:
        if zone_log_match is None:
            return False
        zone_str = zone_log_match.group(2)
        info_fp.write("INFO: Zone is %s\n" % (zone_str, ))
        if zone_str != zone:
            return False

    return True

def include_with_date (after_dt, before_dt, spyglass_link, ci_type_str):
    global output_fp
    global info_fp

    started_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/started.json"
    started_str = get_url_string(started_url)
    started_json = json.loads(started_str)
    started_dt = datetime.utcfromtimestamp(int(started_json['timestamp']))
    # print(started_json['timestamp'])
    after_bool = started_dt >= after_dt
    before_bool = started_dt <= before_dt

    sys.stderr.write("INFO: Started on %s (%s) (%s)\n" % (started_dt, after_bool, before_bool, ))
    if info_fp != sys.stderr:
        info_fp.write("INFO: Started on %s (%s) (%s)\n" % (started_dt, after_bool, before_bool, ))
    if (started_dt >= after_dt) and (started_dt <= before_dt):
        return True
    else:
        return False

def print_test_run (spyglass_link, ci_type_str):
    global green_runs
    global output_fp
    global info_fp

    test_log_junit_dir_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/openshift-e2e-libvirt-test/artifacts/junit/"
    test_log_junit_dir_str = get_url_string(test_log_junit_dir_url)

    test_failure_summary_filename_str = None
    test_failure_summary_filename_re = re.compile('(test-failures-summary_[^.]*\.json)')
    test_failure_summary_filename_match = test_failure_summary_filename_re.search(test_log_junit_dir_str, re.MULTILINE|re.DOTALL)
    if test_failure_summary_filename_match is not None:
        test_failure_summary_filename_str = test_failure_summary_filename_match.group(1)
    else:
        info_fp.write("ERROR: Could not find test-failures-summary_*.json?\n")
        info_fp.write("\n")
        return

    test_log_junit_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/openshift-e2e-libvirt-test/artifacts/junit/" + test_failure_summary_filename_str
    test_log_junit_str = get_url_string(test_log_junit_url)

    test_log_junit_json = json.loads(test_log_junit_str)

    tests = test_log_junit_json['Tests']
    if tests == []:
        output_fp.write("SUCCESS: All tests succeeded!\n")

        green_runs += 1
    else:
        output_fp.write("FAILURE: Failing tests:\n")
        for test in tests:
            output_fp.write("%s\n" % (test['Test']['Name'], ))

    output_fp.write("\n")

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
    parser.add_argument('-d', '--deploy-status-only',
                        action="store_true",
                        dest='deploy_status_only',
                        help='Only show deploy failures')
    parser.add_argument('-o', '--output',
                        type=str,
                        dest='output',
                        nargs=1,
                        help='The filename for output')
    parser.add_argument('-u', '--url',
                        type=str,
                        required=True,
                        dest='url',
                        nargs=1,
                        help='URL of the CI to use')
    parser.add_argument('-v', '--version',
                        dest='version',
                        action='version',
                        version='%(prog)s {version}'.format(version=__version__),
                        help='Display the version of this program')
    parser.add_argument('-z', '--zone',
                        type=str,
                        dest='zone',
                        nargs=1,
                        help='The zone to limit queries on')
    args = parser.parse_args()

    if len(args.url) != 1:
        info_fp.write("ERROR: Expecting exactly one URL\n")
        info_fp.write("ERROR: Usage: ./JobHistory.py https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-serial-ovn-ppc64le-powervs\n")
        sys.exit(1)

    url = args.url[0]
    idx = url.find('https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/')
    if idx == -1:
        info_fp.write("ERROR: unknown CI URL\n")
        exit(1)

    after_str = datetime.min.isoformat()
    if args.after_str is not None:
        after_str = args.after_str[0]
    # print("after_str = " + after_str)
    after_dt = fromisoformat(after_str)
    # print("after_dt = %s" % (after_dt, ))
    if after_dt is None:
        info_fp.write("ERROR: Unknown formatted date %s\n" % (after_str, ))
        sys.exit(1)

    before_str = datetime.utcnow().isoformat()
    if args.before_str is not None:
        before_str = args.before_str[0]
    # print("before_str = " + before_str)
    before_dt = fromisoformat(before_str)
    # print("before_dt = %s" % (before_dt, ))
    if before_dt is None:
        info_fp.write("ERROR: Unknown formatted date %s\n" % (before_str, ))
        sys.exit(1)

    if args.output is not None:
        output_fp = open(args.output[0], "w")
        info_fp = output_fp

    zone_str = None
    if args.zone is not None:
        zone_str = args.zone[0]

    sys.stderr.write("INFO: Finding CI runs between %s and %s\n" % (after_str, before_dt, ))
    sys.stderr.write("\n")

    # Ex:
    # url:
    #   https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs
    # base_url_str:
    #   https://prow.ci.openshift.org
    # ci_str:
    #   periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs
    # ci_version_str:
    #   4.13
    # ci_type_str:
    #   ocp-e2e-ovn-ppc64le-powervs
    parts = url.split('/')
    base_url_str = parts[0] + '//' + parts[2]
    idx = url.rfind('/')
    ci_str = url[idx+1:]
    ci_info_re = re.compile('([^0-9].*)-([0-9]\.[0-9]*)-(.*)')
    ci_info_match = ci_info_re.match(ci_str)
    if ci_info_match is None:
        info_fp.write("ERROR: ci_info_re didn't match?\n")
        exit(1)
    ci_version_str = ci_info_match.group(2)
    ci_type_str = ci_info_match.group(3)

    cj = http.cookiejar.CookieJar()

    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler(),
                                         urllib.request.HTTPHandler(debuglevel=0),
                                         urllib.request.HTTPSHandler(debuglevel=0),
                                         urllib.request.HTTPCookieProcessor(cj))

    while True:

        processed_any = False

        root_response = opener.open(url)
        root_data = get_data(root_response)

        root_soup = BeautifulSoup(root_data, features = "html.parser")

        older_href = None
        for td in root_soup.findAll('td'):
            td_str = td.text
            idx = td_str.find('Older Runs')
            if idx == -1:
                continue
            for child in td.children:
                if 'href' not in child.attrs:
                    continue
                older_href = child.attrs['href']

        for script_bs in root_soup.findAll('script'):
            script_str = script_bs.text
            idx = script_str.find('var allBuilds')
            if idx == -1:
                continue
            table_match = re.search('(var allBuilds = )(\[[^]]+\])(;)', script_str)
            table_str = table_match.group(2)
            table_map = json.loads(table_str)
            for spyglass_link in table_map:

                info_fp.write("INFO: 8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------\n")

                if not include_with_zone (zone_str, spyglass_link, ci_type_str):
                    output_fp.write("\n")
                    continue

                if not include_with_date (after_dt, before_dt, spyglass_link, ci_type_str):
                    output_fp.write("\n")
                    continue

                processed_any = True

                num_deploys += 1

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
                info_fp.write("INFO: %s\n" % (job_url, ))

                # job_response = opener.open(job_url)
                # job_data = get_data(job_response)
                # job_soup = BeautifulSoup(job_data, features = "html.parser")

                build_log_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/ipi-install-powervs-install/build-log.txt"

                build_finished_str = get_url_string("https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/ipi-install-powervs-install/finished.json")
                if build_finished_str.find('<!doctype html>') == -1:
                    build_finished_json = json.loads(build_finished_str)
                else:
                    build_finished_json = {'result': 'FAILURE'}

                if build_finished_json['result'] == 'SUCCESS':
                    output_fp.write("SUCCESS: create cluster succeeded!\n")

                    deploys_succeeded += 1

                    if not args.deploy_status_only:
                        print_test_run(spyglass_link, ci_type_str)
                    else:
                        output_fp.write("\n")
                else:
                    build_log_response = opener.open(build_log_url)
                    build_log_data = get_data(build_log_response)
                    build_log_str = build_log_data.decode()

                    create_cluster_re = re.compile('(.*)(8<--------8<--------8<--------8<-------- BEGIN: create cluster 8<--------8<--------8<--------8<--------\n)(.*)(8<--------8<--------8<--------8<-------- END: create cluster 8<--------8<--------8<--------8<--------\n)(.*)', re.MULTILINE|re.DOTALL)
                    create_cluster_match = create_cluster_re.match(build_log_str)

                    if create_cluster_match is not None:
                        output_fp.write("%s\n" % (create_cluster_match.group(3), ))
                    else:
                        output_fp.write("FAILURE: Could not find create cluster?\n")
                        output_fp.write("\n")

                # pdb.set_trace()

        if older_href is None:
            break
        else:
            if not processed_any:
                # If older runs are outside our date range, why go even older?
                break
            url = base_url_str + older_href

    output_fp.write("\n")
    output_fp.write("Finished\n")
    output_fp.write("%d/%d deploys succeeded\n" % (deploys_succeeded, num_deploys, ))
    if not args.deploy_status_only:
        output_fp.write("%d/%d e2e green runs\n" % (green_runs, num_deploys, ))
