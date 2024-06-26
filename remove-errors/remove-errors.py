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

    # Read in the file
    with open(directory + filename, "r") as fp_in:
        data = fp_in.read()

#   pdb.set_trace()

    b_using_errors  = False
    b_inside_import = False
    b_found_fmt     = False
    b_found_errors  = False
    b_using_new     = False

    for line in data.splitlines():
        # Are we using an errors function?
        idx = line.find('errors.')
        if idx > -1:
            # Is there something after the errors. part?
            if len(line) - idx > 7:
                b_using_errors = True
        if re.search(re_new, line):
            b_using_new = True

    # Write out the processed file
    with open(directory + filename, "w") as fp_out:
        for line in data.splitlines():
            # Handle missing "fmt" in import block
            if re.search(re_begin_import, line):
                b_inside_import = True
            if re.search(re_end_import, line) and b_inside_import:
                if not b_found_fmt and b_using_errors:
                    fp_out.write('\t"fmt"\n')
                if not b_found_errors and b_using_new:
                    fp_out.write('\t"errors"\n')
                b_inside_import = False
            if b_inside_import:
                if re.search(re_fmt, line):
                    b_found_fmt = True
                if re.search(re_errors, line):
                    b_found_errors = True
            # Remove the errors package
            if line.find('"github.com/pkg/errors"') > -1:
                continue
#           elif line.find('"errors"') > -1:
#               continue
            # Are we using an errors function?
            if line.find('errors.') > -1:
                line = handle_line(line)
                line = fixup_err_parameter(line)
#               print(line)
            fp_out.write(line+'\n')

def handle_line(line):
    if re.search(re_wrapf, line):
        line = handle_Wrapf(line)
    elif re.search(re_wrap, line):
        line = handle_Wrap(line)
    elif re.search(re_errorf, line):
        line = handle_Errorf(line)
#   elif re.search(re_new, line):
#       line = handle_New(line)

    # Avoid lint error about uppercase error messages
    idx_message = line.find('("')
    if idx_message > -1:
        idx_message += 2
#       print(line[:idx_message] + '^' + line[idx_message+1:])
        b_all_upper = False
        idx_space = line[idx_message:].find(' ')
        if idx_space > -1:
#           print(line[idx_message:idx_message+idx_space]+"$$$")
            b_all_upper = line[idx_message:idx_message+idx_space].isupper()
        if not b_all_upper:
            line = line[:idx_message] + line[idx_message].lower() + line[idx_message+1:]
#           print(line)

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
    line = re_wrapf.sub('fmt.Errorf(', line)
#   print(line)
    line = re_lparen_err_comma.sub('(', line)
#   print(line)
    # Rarely, the code already prints out the error at the end.  So ignore this case.
    if not (b_Err_at_end or b_Err_in_middle):
        line = re_lparen.sub(', err)', line)
#       print(line)
        line = fixup_end_quote(line)
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
    line = re_wrap.sub('fmt.Errorf(', line)
#   print(line)
    line = re_lparen_err_comma.sub('(', line)
#   print(line)
    # Rarely, the code already prints out the error at the end.  So ignore this case.
    if not (b_Err_at_end or b_Err_in_middle):
        line = re_lparen.sub(', err)', line)
#       print(line)
        line = fixup_end_quote(line)
#       print(line)
#   print('8<------8<------8<------8<------8<------8<------8<------8<------')

    return line

def handle_Errorf(line):
    # FROM:
    # return errors.Errorf("destroyPublicGateways: %d undeleted items pending", len(items))
    # TO:
    # return fmt.Errorf("destroyPublicGateways: %d undeleted items pending", len(items))
    line = re_errorf.sub('fmt.Errorf(', line)

    return line

def handle_New(line):
    # FROM:
    # return nil, errors.New("newAuthenticator: apikey is empty")
    # TO:
    # return nil, fmt.Errorf("newAuthenticator: apikey is empty")
    line = re_new.sub('fmt.Errorf(', line)

    return line

def fixup_end_quote(line):
    idx_end_quote = line.rfind('",')
    if idx_end_quote == -1:
        return line

#   print('FROM: '+line)

    line1 = line[:idx_end_quote]
    line2 = line[idx_end_quote:]
#   print('LINE1: '+line1)
#   print('LINE2: '+line2)
    line2 = re_quote_comma.sub(': %w",', line2)
    line = line1 + line2

#   print('TO:   '+line)

    return line

def fixup_err_parameter(line):
#   print('FROM: '+line)

    match_split_params = re.match(re_split_params, line)
#   print('match_split_params = %s' % (match_split_params, ))

    if not match_split_params:
        return line

    # Split the string into the parts we don't care about and the part we do
    full_params = match_split_params.group(2)
    parms = full_params.split(',')

    # Is err a paramter?
    i_err_parameter = -1
    for i in range(len(parms)):
        if 'err' == parms[i].strip():
            i_err_parameter = i

    if i_err_parameter > -1:
#       pdb.set_trace()

        string = parms[0]

        # First find the matching %
        idx = -1
        for i in range(i_err_parameter):
            if idx == -1:
                idx = string.find('%')
            else:
                idx = string.find('%', idx+1)

        if idx > -1:
            # Now replace that paramter with %w
            begin    = string[:idx]
            end      = string[idx+2:]
            string   = begin + '%w' + end

            # Then build the line back up
            new_line = match_split_params.group(1) + string
            for parm in parms[1:]:
                new_line += ',' + parm
            new_line += match_split_params.group(3)
            line = new_line

#   print('TO:   '+line)

    return line

re_begin_import     = re.compile('^import \($')
re_fmt              = re.compile('"fmt"')
re_errors           = re.compile('"errors"')
re_end_import       = re.compile('^\)$')
re_lparen_err_comma = re.compile('\(err, ')
re_quote_comma      = re.compile('",')
re_lparen           = re.compile('\)$')
re_wrapf            = re.compile('errors.Wrapf\(')
re_wrap             = re.compile('errors.Wrap\(')
re_errorf           = re.compile('errors.Errorf\(')
re_new              = re.compile('errors.New\(')
re_split_params     = re.compile('(^[^(]*\()([^)]*)(\).*$)')

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

        # If we find a powervs directory, then process every file in that directory
        if 'powervs' in path:
            for filename in files:
                handle_file(root, filename)
