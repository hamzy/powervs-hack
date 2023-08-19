#!/usr/bin/env python3
#
# (remove-errors/remove-errors.py --directory remove-errors/; git diff remove-errors/powervs/; git restore remove-errors/powervs/)
#

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
    b_Wrapf = line.find('errors.Wrapf') > -1
    if b_Wrapf:
        line = handle_Wrapf(line)

    b_Wrap = line.find('errors.Wrap') > -1
    if b_Wrap:
        line = handle_Wrap(line)

    b_Errorf = line.find('errors.Errorf') > -1
    if b_Errorf:
        line = handle_Errorf(line)

    b_New = line.find('errors.New') > -1
    if b_New:
        line = handle_New(line)

    return line

def handle_Wrapf(line):
    # FROM:
    # return errors.Wrapf(err, "failed to delete publicGateway %s", item.name)
    # return nil, errors.Wrapf(err, "failed to list Cloud ssh keys: %v and the response is: %s", err, detailedResponse)
    # TO:
    # return fmt.Errorf("failed to delete publicGateway %s: %w", item.name, err)
    # return nil, fmt.Errorf("failed to list Cloud ssh keys: %w and the response is: %s", err, detailedResponse)
#   print('8<------8<------8<------8<------8<------8<------8<------8<------')
    b_Err_at_end = line.find(', err)') > -1
    b_Err_in_middle = line.find(', err,') > -1
#   print('line = %s' % (line, ))
#   print('b_Err_at_end = %s, idx = %s' % (b_Err_at_end, line.find(', err)'), ))
#   print('b_Err_in_middle = %s, idx = %s' % (b_Err_in_middle, line.find(', err,'), ))
    line = re_wrapf.sub('fmt.Errorf', line)
#   print(line)
    line = re_lparen_err_comma.sub('(', line)
#   print(line)
    # Rarely, the code already prints out the error at the end.  So ignore this case.
    if not (b_Err_at_end or b_Err_in_middle):
        line = re_lparen.sub(', err)', line)
#       print(line)
        line = re_quote_comma.sub(': %w",', line)
#       print(line)
#   print('8<------8<------8<------8<------8<------8<------8<------8<------')

    return line

def handle_Wrap(line):
    # FROM:
    # return nil, errors.Wrap(err, "Failed to list resource instances")
    # TO:
    # return nil, fmt.Errorf("Failed to list resource instances: %w", err)
#   print('8<------8<------8<------8<------8<------8<------8<------8<------')
    b_Err_at_end = line.find(', err)') > -1
    b_Err_in_middle = line.find(', err,') > -1
#   print('line = %s' % (line, ))
#   print('b_Err_at_end = %s, idx = %s' % (b_Err_at_end, line.find(', err)'), ))
#   print('b_Err_in_middle = %s, idx = %s' % (b_Err_in_middle, line.find(', err,'), ))
    line = re_wrap.sub('fmt.Errorf', line)
#   print(line)
    line = re_lparen_err_comma.sub('(', line)
#   print(line)
    # Rarely, the code already prints out the error at the end.  So ignore this case.
    if not (b_Err_at_end or b_Err_in_middle):
        line = re_lparen.sub(', err)', line)
#       print(line)
        line = re_quote_comma.sub(': %w",', line)
#       print(line)
#   print('8<------8<------8<------8<------8<------8<------8<------8<------')

    return line

def handle_Errorf(line):
    # FROM:
    # return errors.Errorf("destroyPublicGateways: %d undeleted items pending", len(items))
    # TO:
    # return fmt.Errorf("destroyPublicGateways: %d undeleted items pending", len(items))
    line = re_errorf.sub('fmt.Errorf', line)

    return line

def handle_New(line):
    # FROM:
    # return nil, errors.New("newAuthenticator: apikey is empty")
    # TO:
    # return nil, fmt.Errorf("newAuthenticator: apikey is empty")
    line = re_new.sub('fmt.Errorf', line)

    return line

re_wrapf            = re.compile('errors.Wrapf')
re_wrap             = re.compile('errors.Wrap')
re_lparen_err_comma = re.compile('\(err, ')
re_quote_comma      = re.compile('",')
re_lparen           = re.compile('\)$')
re_errorf           = re.compile('errors.Errorf')
re_new              = re.compile('errors.New')

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
