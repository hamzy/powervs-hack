#!/usr/bin/env python3

# Running this program:
# $ python3 -m venv venv
# $ source venv/bin/activate
# $ pip install --upgrade pip
# $ pip install --requirement requirements.txt
#
# (venv) hamzy:DhcpFailedPrivateNetwork$ ./DhcpFailedPrivateNetwork.py --url https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/periodic-ci-openshift-multiarch-master-nightly-4.17-ocp-e2e-ovn-powervs-capi-multi-p-p

# 0.1 on 2025-03-18
__version__ = "0.1"
__date__ = "2025-03-18"
__author__ = "Mark Hamzy (mhamzy@redhat.com)"

import argparse
from bs4 import BeautifulSoup
from datetime import date
from datetime import datetime
from datetime import timedelta
from datetime import timezone
import gzip
import http.cookiejar
import io
import json
import pdb
import pytz
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
    zone_log_re = re.compile('(Acquired 1 lease\\(s\\) for powervs-[1-9]-quota-slice: \\[)([^]]+)(\\])', re.MULTILINE|re.DOTALL)
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
    #started_dt = datetime.utcfromtimestamp(int(started_json['timestamp']))
    started_dt = datetime.fromtimestamp(int(started_json['timestamp']), timezone.utc)

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

def gather_build_run(opener, spyglass_link, ci_type_str, failed_create_map, current_zone_str):
    build_log_url = "https://gcsweb-ci.apps.ci.l2s4.p1.openshiftapps.com/gcs" + spyglass_link['SpyglassLink'][8:] + "/artifacts/" + ci_type_str + "/ipi-install-powervs-install/build-log.txt"
    build_log_response = opener.open(build_log_url)
    build_log_data = get_data(build_log_response)
    build_log_str = build_log_data.decode()

    # message: 'failed to perform Create DHCP Operation for cloud instance XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX with error [POST /pcloud/v1/cloud-instances/{cloud_instance_id}/services/dhcp][500] pcloudDhcpPostInternalServerError {"description":"dhcp server failed to create private network: unable to retrieve active status for new PER connection information after create private network 4fcbf528-386a-4188-a60f-5d1d68890022: %!!(MISSING)w(\u003cnil\u003e)","error":"internal server error"}'
    failed_create_re = re.compile('unable to retrieve active status for new PER connection information after create private network ([-a-f0-9]*): %!!\\(MISSING\\)', re.DOTALL)
    failed_create_search = failed_create_re.search(build_log_str)
    if failed_create_search is None:
        return

    if current_zone_str not in failed_create_map:
        failed_create_map[current_zone_str] = []
    failed_create_map[current_zone_str] += [failed_create_search.group(1)]

def fromisoformat (date_str):
    # Argh! New in version 3.7: datetime.fromisoformat :(
    # dt = datetime.fromisoformat(date_str)

    # https://en.wikipedia.org/wiki/ISO_8601
    recognized_formats = [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d"
    ]

    dt = None
    for date_format in recognized_formats:
        try:
            dt = datetime.strptime(date_str, date_format).replace(tzinfo=pytz.utc)
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

def process_url(args, url, failed_create_map):
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
    ci_info_re = re.compile('([^0-9].*)-([0-9]\\.[0-9]*)-(.*)')
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
        for td in root_soup.find_all('td'):
            td_str = td.text
            idx = td_str.find('Older Runs')
            if idx == -1:
                continue
            for child in td.children:
                if 'href' not in child.attrs:
                    continue
                older_href = child.attrs['href']

        for script_bs in root_soup.find_all('script'):
            script_str = script_bs.text
            idx = script_str.find('var allBuilds')
            if idx == -1:
                continue
            table_match = re.search('(var allBuilds = )(\\[[^]]+\\])(;)', script_str)
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

                current_zone_str = get_zone(opener, spyglass_link, ci_type_str)

                # Test if we should process this run against a date restriction
                if not include_with_date (opener, after_dt, before_dt, spyglass_link, ci_type_str):
                    continue

                # Test if we should process this run against a zone restriction
                if current_zone_str is None:
                    info_fp.write("INFO: URL:  %s\n" % (job_url, ))
                    info_fp.write("ERROR: Could not find the zone?\n\n")
                    continue
                else:
                    if (zone_str is not None) and (current_zone_str != zone_str):
                        continue

                processed_any = True

                info_fp.write("INFO: URL:  %s\n" % (job_url, ))
                info_fp.write("INFO: Zone: %s\n" % (current_zone_str, ))

                gather_build_run(opener, spyglass_link, ci_type_str, failed_create_map, current_zone_str)

        if older_href is None:
            break
        else:
            if not processed_any:
                # If older runs are outside our date range, why go even older?
                break
            url = base_url_str + older_href

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
    parser.add_argument('-l', '--last-n-days',
                        type=str,
                        dest='last_n_days',
                        nargs=1,
                        help='Only queries for the last n days')
    parser.add_argument('-o', '--output',
                        type=str,
                        dest='output',
                        nargs=1,
                        help='The filename for output')
    parser.add_argument('--today',
                        action="store_true",
                        dest='today',
                        help='Only queries for today')
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
    parser.add_argument('--yesterday',
                        action="store_true",
                        dest='yesterday',
                        help='Only queries for yesterday')
    parser.add_argument('-z', '--zone',
                        type=str,
                        dest='zone',
                        nargs=1,
                        help='The zone to limit queries on')
    args = parser.parse_args()

    if args.today:
        if args.after_str is not None:
            info_fp.write("ERROR: Cannot have both --after-date and --today\n")
            sys.exit(1)
        if args.before_str is not None:
            info_fp.write("ERROR: Cannot have both --before-date and --today\n")
            sys.exit(1)
        if args.yesterday:
            info_fp.write("ERROR: Cannot have both --yesterday and --today\n")
            sys.exit(1)
        if args.last_n_days is not None:
            info_fp.write("ERROR: Cannot have both --last-n-days and --today\n")
            sys.exit(1)
        today = date.today()
        after_dt = datetime(date.today().year, date.today().month, date.today().day).replace(tzinfo=pytz.utc)
        after_str = after_dt.isoformat()
        before_dt = datetime(date.today().year, date.today().month, date.today().day, 23, 59, 59, 999999).replace(tzinfo=pytz.utc)
        before_str = before_dt.isoformat()
    elif args.yesterday:
        if args.after_str is not None:
            info_fp.write("ERROR: Cannot have both --after-date and --yesterday\n")
            sys.exit(1)
        if args.before_str is not None:
            info_fp.write("ERROR: Cannot have both --before-date and --yesterday\n")
            sys.exit(1)
        if args.today:
            info_fp.write("ERROR: Cannot have both --yesterday and --today\n")
            sys.exit(1)
        if args.last_n_days is not None:
            info_fp.write("ERROR: Cannot have both --last-n-days and --yesterday\n")
            sys.exit(1)
        yesterday = date.today() - timedelta(days=1)
        after_dt = datetime(yesterday.year, yesterday.month, yesterday.day).replace(tzinfo=pytz.utc)
        after_str = after_dt.isoformat()
        before_dt = datetime(yesterday.year, yesterday.month, yesterday.day, 23, 59, 59, 999999).replace(tzinfo=pytz.utc)
        before_str = before_dt.isoformat()
    elif args.last_n_days:
        if args.today:
            info_fp.write("ERROR: Cannot have both --last-n-days and --today\n")
            sys.exit(1)
        if args.yesterday:
            info_fp.write("ERROR: Cannot have both --last-n-days and --yesterday\n")
            sys.exit(1)
        last_days = int(args.last_n_days[0]) - 1
        last_date = date.today() - timedelta(days=last_days)
        # print("last_days = " + str(last_days))
        # print("last_date = " + str(last_date))
        after_dt = datetime(last_date.year, last_date.month, last_date.day).replace(tzinfo=pytz.utc)
        after_str = after_dt.isoformat()
        before_dt = datetime(date.today().year, date.today().month, date.today().day, 23, 59, 59, 999999).replace(tzinfo=pytz.utc)
        before_str = before_dt.isoformat()
    else:
        after_str = datetime.min.isoformat()
        #before_str = datetime.utcnow().isoformat()
        before_str = datetime.now(timezone.utc).isoformat()

    if args.after_str is not None:
        after_str = args.after_str[0]
    # print("after_str = " + after_str)
    after_dt = fromisoformat(after_str)
    # print("after_dt = %s" % (after_dt, ))
    if after_dt is None:
        info_fp.write("ERROR: Unknown formatted date %s\n" % (after_str, ))
        sys.exit(1)

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

    short_map = {
        'lon06-powervs-7-quota-slice-0': 'lon06-0',
        'lon06-powervs-7-quota-slice-1': 'lon06-1',
        'lon06-powervs-7-quota-slice-2': 'lon06-2',
        'lon06-powervs-7-quota-slice-3': 'lon06-3',
    }
    guid_map = {
        'lon06-powervs-7-quota-slice-0': '89fc8fc4-3e87-4806-b1c5-5d1d30dbca0a',
        'lon06-powervs-7-quota-slice-1': '55282780-84e5-49da-9e7c-bc51f5dd14d0',
        'lon06-powervs-7-quota-slice-2': '369c64ef-073e-424b-ba18-9b4040780642',
        'lon06-powervs-7-quota-slice-3': 'e8169d7d-b1ff-49ec-8170-bb408bc23321'
    }
    failed_create_map = {}

    for url in args.url:
        idx = url.find('https://prow.ci.openshift.org/job-history/gs/origin-ci-test/logs/')
        if idx == -1:
            info_fp.write("ERROR: unknown CI URL\n")
            exit(1)

        process_url(args, url, failed_create_map)

    for key in failed_create_map.keys():
        crn = 'crn:v1:bluemix:public:power-iaas:lon06:a/3c24cb272ca44aa1ac9f6e9490ac5ecd:%s::' % (guid_map[key],)
        items = failed_create_map[key]
        info_fp.write("%s: %s\n" % (short_map[key], crn, ))
        for item in items:
            info_fp.write("\t%s\n" % (item,))
