#!/usr/bin/env python3

# Running this program:
# $ python3 -m venv venv
# $ source venv/bin/activate
# $ pip install --upgrade pip
# $ pip install --requirement requirements.txt
#
# (venv) JobHistory2$ ./JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs
#
# (venv) JobHistory2$ ./JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-serial-ovn-ppc64le-powervs
#
# (venv) JobHistory2$ ./JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.14-ocp-e2e-ovn-ppc64le-powervs
#
# (venv) JobHistory2$ ./JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.14-ocp-e2e-serial-ovn-ppc64le-powervs
#
# (venv) ./JobHistory.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.14-ocp-e2e-ovn-ppc64le-powervs https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.14-ocp-e2e-serial-ovn-ppc64le-powervs https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-serial-ovn-ppc64le-powervs --today --csv --output output.csv


# 0.1 on 2020-06-14
# 0.2 on 2023-04-10
# 0.3 on 2023-04-11
# 0.3.1 on 2023-04-12
# 0.4 on 2023-04-12
# 0.5 on 2023-04-13
# 0.6 on 2023-04-13
# 0.7 on 2023-04-14
# 0.7.1 on 2023-04-14
# 0.8 on 2023-04-15
# 0.8.1 on 2023-04-21
# 0.8.2 on 2023-04-21
# 0.8.3 on 2023-04-21
# 0.9.0 on 2023-04-29
# 0.9.1 on 2023-05-25
# 0.9.2 on 2023-06-08
# 0.9.3 on 2023-06-27
# 0.9.4 on 2023-07-20
__version__ = "0.9.4"
__date__ = "2023-07-20"
__author__ = "Mark Hamzy (mhamzy@redhat.com)"

import argparse
from bs4 import BeautifulSoup
import csv
from datetime import date
from datetime import datetime
from datetime import timedelta
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

def get_url_string(opener, url):
    url_response = opener.open(url)
    url_data = get_data(url_response)
    try:
        return url_data.decode()
    except UnicodeDecodeError:
        # 0x80 is not valid ASCII or UTF-8 so fails.
        # 0x80 is valid in some characters sets. In windows-1252/cp1252 it's €.
        for remove in [ b'\x80', b'\x81', b'\x82', b'\x83' ]:
            url_data = url_data.replace(remove, b' ')
        return url_data.decode()

def get_data(response):
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

def get_zone (opener, spyglass_link, ci_type_str):
    zone_log_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/build-log.txt"
    zone_log_str = get_url_string(opener, zone_log_url)
    zone_log_re = re.compile('(Acquired 1 lease\(s\) for powervs-[1-9]-quota-slice: \[)([^]]+)(\])', re.MULTILINE|re.DOTALL)
    zone_log_match = zone_log_re.search(zone_log_str)
    if zone_log_match is None:
        return None
    else:
        return zone_log_match.group(2)

def include_with_date (opener, after_dt, before_dt, spyglass_link, ci_type_str):
    global info_fp

    started_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/started.json"
    started_str = get_url_string(opener, started_url)
    started_json = json.loads(started_str)
    started_dt = datetime.utcfromtimestamp(int(started_json['timestamp']))
    # print(started_json['timestamp'])
    after_bool = started_dt >= after_dt
    before_bool = started_dt <= before_dt

#   sys.stderr.write("INFO: Started on %s (%s) (%s)\n" % (started_dt, after_bool, before_bool, ))
#   if info_fp != sys.stderr:
#       info_fp.write("INFO: Started on %s (%s) (%s)\n" % (started_dt, after_bool, before_bool, ))
    if (started_dt >= after_dt) and (started_dt <= before_dt):
        return True
    else:
        return False

def gather_build_run(opener, spyglass_link, ci_type_str):
    build_finished_json = {'result': 'FAILURE'}

    build_summary_str = ""
    build_details_str = ""

    build_finished_str = get_url_string(opener, "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/ipi-install-powervs-install/finished.json")
    if build_finished_str.find('<!doctype html>') == -1:
        build_finished_json = json.loads(build_finished_str)

    if build_finished_json['result'] == 'SUCCESS':
        build_summary_str = "SUCCESS: create cluster succeeded!"

        return (build_finished_json, build_summary_str, build_details_str)

    build_log_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/ipi-install-powervs-install/build-log.txt"
    build_log_response = opener.open(build_log_url)
    build_log_data = get_data(build_log_response)
    build_log_str = build_log_data.decode()

    create_cluster_re = re.compile('(.*)(8<--------8<--------8<--------8<-------- BEGIN: create cluster 8<--------8<--------8<--------8<--------\n)(.*)(8<--------8<--------8<--------8<-------- END: create cluster 8<--------8<--------8<--------8<--------\n)(.*)', re.MULTILINE|re.DOTALL)
    create_cluster_match = create_cluster_re.match(build_log_str)

    if create_cluster_match is not None:
        build_summary_str = "FAILURE: create cluster failed!"
        build_details_str = create_cluster_match.group(3)
    else:
        build_summary_str = "FAILURE: Could not find create cluster?"

    return (build_finished_json, build_summary_str, build_details_str)

def gather_test_run (opener, spyglass_link, ci_type_str):
    test_summary_str = ""
    test_details_str = ""

    test_log_junit_dir_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/openshift-e2e-libvirt-test/artifacts/junit/"
    test_log_junit_dir_str = get_url_string(opener, test_log_junit_dir_url)

    test_failure_summary_filename_str = None
    test_failure_summary_filename_re = re.compile('(test-failures-summary_[^.]*\.json)')
    test_failure_summary_filename_match = test_failure_summary_filename_re.search(test_log_junit_dir_str, re.MULTILINE|re.DOTALL)
    if test_failure_summary_filename_match is not None:
        test_failure_summary_filename_str = test_failure_summary_filename_match.group(1)
    else:
        test_summary_str = "ERROR: Could not find test-failures-summary_*.json?"

        return (test_summary_str, test_details_str)

    test_log_junit_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/openshift-e2e-libvirt-test/artifacts/junit/" + test_failure_summary_filename_str
    test_log_junit_str = get_url_string(opener, test_log_junit_url)

    test_log_junit_json = json.loads(test_log_junit_str)

    tests = test_log_junit_json['Tests']
    if tests == []:
        test_summary_str = "SUCCESS: All tests succeeded!"

        ci_stats['green_runs'] += 1
    else:
        test_summary_str = "FAILURE: Failing tests:"
        for test in tests:
            test_details_str += ("%s\n" % (test['Test']['Name'], ))

    # pdb.set_trace()

    return (test_summary_str, test_details_str)

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

def encode_string(input_str):
#   return input_str.replace("\n", "\\n")
#   encoded_str = input_str.encode("unicode_escape").decode("utf-8")
#   print("input_str = %s\n" % (input_str, ))
#   print("encoded_str = %s\n" % (encoded_str, ))
    return input_str.encode("unicode_escape").decode("utf-8")

def process_url(args, ci_stats, url):
    zone_str = None
    if args.zone is not None:
        zone_str = args.zone[0]

    sys.stderr.write("INFO: For URL %s\n" % (url, ))
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
            table_json = json.loads(table_str)
            for spyglass_link in table_json:

                # Ex:
                # {'SpyglassLink': '/view/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.12-ocp-e2e-ovn-ppc64le-powervs/1620753919086956544', 'ID': '1620753919086956544', 'Started': '2023-02-01T12:00:25Z', 'Duration': 12390000000000, 'Result': 'FAILURE', 'Refs': None}
                # 
                # job_url:
                #   https://prow.ci.openshift.org/view/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs/1645426556757086208
                # build_log_url:
                #   https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.13-ocp-e2e-ovn-ppc64le-powervs/1645426556757086208/artifacts/ocp-e2e-ovn-ppc64le-powervs/ipi-install-powervs-install/build-log.txt

                build_summary_str = ""
                build_details_str = ""
                test_summary_str  = ""
                test_details_str  = ""

                job_url = "https://prow.ci.openshift.org" + spyglass_link['SpyglassLink']

                info_fp.write("INFO: 8<--------8<--------8<--------8<--------8<--------8<--------8<--------8<--------\n")
                info_fp.write("INFO: URL:  %s\n" % (job_url, ))
                info_fp.write("INFO: Zone: %s\n" % (current_zone_str, ))

                (build_finished_json, build_summary_str, build_details_str) = gather_build_run(opener, spyglass_link, ci_type_str)

                (test_summary_str, test_details_str) = gather_test_run(opener, spyglass_link, ci_type_str)

        if older_href is None:
            break
        else:
            url = base_url_str + older_href

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Extract CI runs')
    parser.add_argument('-o', '--output',
                        type=str,
                        dest='output',
                        nargs=1,
                        help='The filename for output')
    parser.add_argument('-s', '--search',
                        type=str,
                        dest='search',
                        nargs=1,
                        help='The search string')
    parser.add_argument('-u', '--url',
                        type=str,
                        required=True,
                        dest='url',
                        nargs='+',
                        help='URL of the CI to use')
    parser.add_argument('-v', '--version',
                        dest='version',
                        action='version',
                        version='%(prog)s {version}'.format(version=__version__),
                        help='Display the version of this program')
    args = parser.parse_args()

    if args.output is not None:
        output_fp = open(args.output[0], "w")
        if not args.csv:
          info_fp = output_fp

    for url in args.url:
        idx = url.find('https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/')
        if idx == -1:
            info_fp.write("ERROR: unknown CI URL\n")
            exit(1)

        process_url(args, ci_stats, url)

    info_fp.write("Finished\n")
