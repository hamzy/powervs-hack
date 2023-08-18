#!/usr/bin/env python3

import argparse
import os
import pdb
import re
import tempfile

# tempfile.NamedTemporaryFile(mode='w', delete=False)

def handle_file(directory, filename):

    if not directory.endswith(os.sep):
        directory += os.sep

    print(directory + filename)

    with open(directory + filename, "r") as fp_in:
        data = fp_in.read()

    with open(directory + filename, "w") as fp_out:
        for line in data.splitlines():
            idx = line.find('"github.com/pkg/errors"')
            if idx > -1:
                continue
            idx = line.find('"errors"')
            if idx > -1:
                continue
            idx = line.find('errors.')
            if idx > -1:
                line = handle_line(line)
#               print(line)
            fp_out.write(line+'\n')

def handle_line(line):
    idx = line.find('errors.Wrapf')
    if idx > -1:
        # FROM:
        # return errors.Wrapf(err, "failed to delete publicGateway %s", item.name)
        # TO:
        # return fmt.Errorf("failed to delete publicGateway %s: %w", item.name, err)
#       print('8<------8<------8<------8<------8<------8<------8<------8<------')
#       print(line)
        line = re_wrapf.sub('fmt.Errorf', line)
#       print(line)
        line = re_err.sub('', line)
#       print(line)
        line = re_quote.sub(': %w",', line)
#       print(line)
        # Rarely, the code already prints out the error at the end.  So ignore this case.
        idx = line.find(', err)')
        if idx == -1:
            line = re_lparen.sub(', err)', line)
#           print(line)
#       print('8<------8<------8<------8<------8<------8<------8<------8<------')

    idx = line.find('errors.Wrap')
    if idx > -1:
        # FROM:
        # return nil, errors.Wrap(err, "Failed to list resource instances")
        # TO:
        # return nil, fmt.Errorf("Failed to list resource instances: %w", err)
#       print('8<------8<------8<------8<------8<------8<------8<------8<------')
#       print(line)
        line = re_wrap.sub('fmt.Errorf', line)
#       print(line)
        line = re_err.sub('', line)
#       print(line)
        line = re_quote.sub(': %w",', line)
#       print(line)
        # Rarely, the code already prints out the error at the end.  So ignore this case.
        idx = line.find(', err)')
        if idx == -1:
            line = re_lparen.sub(', err)', line)
#           print(line)
#       print('8<------8<------8<------8<------8<------8<------8<------8<------')

    idx = line.find('errors.Errorf')
    if idx > -1:
        # FROM:
        # return errors.Errorf("destroyPublicGateways: %d undeleted items pending", len(items))
        # TO:
        # return fmt.Errorf("destroyPublicGateways: %d undeleted items pending", len(items))
        line = re_errorf.sub('fmt.Errorf', line)

    idx = line.find('errors.New')
    if idx > -1:
        # FROM:
        # return nil, errors.New("newAuthenticator: apikey is empty")
        # TO:
        # return nil, fmt.Errorf("newAuthenticator: apikey is empty")
        line = re_new.sub('fmt.Errorf', line)

    return line

re_wrapf  = re.compile('errors.Wrapf')
re_wrap   = re.compile('errors.Wrap')
re_err    = re.compile('err, ')
re_quote  = re.compile('",')
re_lparen = re.compile('\)$')
re_errorf = re.compile('errors.Errorf')
re_new    = re.compile('errors.New')

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Fix errors occurances')
    parser.add_argument('-d', '--directory',
                        type=str,
                        dest='directory',
                        nargs=1,
                        help='Directory to process')
    args = parser.parse_args()

    start_directory = '.'
    if args.directory:
        start_directory = args.directory[0]

#   pdb.set_trace()

    # traverse root directory, and list directories as dirs and files as files
    for root, dirs, files in os.walk(start_directory):
        path = root.split(os.sep)

#       print((len(path) - 1) * '---', os.path.basename(root))
#       for file in files:
#           print(len(path) * '---', file)

        if 'powervs' in path:
#           pdb.set_trace()
            for filename in files:
                handle_file(root, filename)
