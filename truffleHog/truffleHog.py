#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
import shutil
import sys
import math
import datetime
import argparse
import uuid
import tempfile
import os
import re
import json
import stat
from git import Repo
from git import NULL_TREE
from truffleHogRegexes.regexChecks import regexes as default_regexes

def load_regexes(regexes_fname):
    """Loads and compiles custom regular expressions from given JSON file"""
    try:
        with open(regexes_fname, "r") as regexes_file:
            regexes_content = regexes_file.read()
    except (IOError) as e:
        raise Exception("Error reading regexes file") from e

    try:
        regexes = {
            label: re.compile(regex)
            for (label, regex) in json.loads(regexes_content).items()
        }
    except (IOError, ValueError) as e:
        raise Exception("Error parsing regexes file") from e

    return regexes

def config_from_args():
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('--json', dest="output_json", action="store_true", help="Output in JSON", default=False)
    parser.add_argument("--regex", dest="do_regex", action="store_true", help="Enable high signal regex checks", default=False)
    parser.add_argument("--regex_file", dest="regex_file", help="Ignore default regexes and source from json list file")
    parser.add_argument("--entropy", dest="do_entropy", help="Enable entropy checks", default="true")
    parser.add_argument("--since_commit", dest="since_commit", help="Only scan from a given commit hash")
    parser.add_argument("--max_depth", dest="max_depth", help="The max commit depth to go back when searching for secrets", default=1_000_000)
    parser.add_argument('git_url', type=str, help='URL for secret searching')

    config = parser.parse_args()

    if config.regex_file:
        config.regexes = load_regexes(config.regex_file)
    else:
        config.regexes = default_regexes

    config.do_entropy = str2bool(config.do_entropy)

    return config

def main():
    config = config_from_args()
    results = find_strings(config)
    output_results(results, config.output_json)

def str2bool(v):
    if v == None:
        return True
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)

def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def clone_git_repo(git_url):
    project_path = tempfile.mkdtemp()
    Repo.clone_from(git_url, project_path)
    return project_path

def output_results(results, print_json):
    if print_json:
        print(json.dumps(results, sort_keys=True))
        return

    for issue in results:
        print_issue(issue)

def print_issue(issue):
    commit_time = issue['date']
    branch_name = issue['branch']
    prev_commit = issue['commit']
    printableDiff = issue['printDiff']
    commit_hash = issue['commitHash']
    reason = issue['reason']
    path = issue['path']

    print("~~~~~~~~~~~~~~~~~~~~~")
    reason = "{}Reason: {}{}".format(bcolors.OKGREEN, reason, bcolors.ENDC)
    print(reason)
    dateStr = "{}Date: {}{}".format(bcolors.OKGREEN, commit_time, bcolors.ENDC)
    print(dateStr)
    hashStr = "{}Hash: {}{}".format(bcolors.OKGREEN, commit_hash, bcolors.ENDC)
    print(hashStr)
    filePath = "{}Filepath: {}{}".format(bcolors.OKGREEN, path, bcolors.ENDC)
    print(filePath)

    if sys.version_info >= (3, 0):
        branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name, bcolors.ENDC)
        print(branchStr)
        commitStr = "{}Commit: {}{}".format(bcolors.OKGREEN, prev_commit, bcolors.ENDC)
        print(commitStr)
        print(printableDiff)
    else:
        branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name.encode('utf-8'), bcolors.ENDC)
        print(branchStr)
        commitStr = "{}Commit: {}{}".format(bcolors.OKGREEN, prev_commit.encode('utf-8'), bcolors.ENDC)
        print(commitStr)
        print(printableDiff.encode('utf-8'))
    print("~~~~~~~~~~~~~~~~~~~~~")

def find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob, commit_hash):
    stringsFound = []
    lines = printableDiff.split("\n")
    for line in lines:
        for word in line.split():
            base64_strings = get_strings_of_set(word, BASE64_CHARS)
            hex_strings = get_strings_of_set(word, HEX_CHARS)
            for string in base64_strings:
                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                if b64Entropy > 4.5:
                    stringsFound.append(string)
                    printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
            for string in hex_strings:
                hexEntropy = shannon_entropy(string, HEX_CHARS)
                if hexEntropy > 3:
                    stringsFound.append(string)
                    printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
    entropicDiff = None
    if len(stringsFound) > 0:
        entropicDiff = {}
        entropicDiff['date'] = commit_time
        entropicDiff['path'] = blob.b_path if blob.b_path else blob.a_path
        entropicDiff['branch'] = branch_name
        entropicDiff['commit'] = prev_commit.message
        entropicDiff['diff'] = blob.diff.decode('utf-8', errors='replace')
        entropicDiff['stringsFound'] = stringsFound
        entropicDiff['printDiff'] = printableDiff
        entropicDiff['commitHash'] = commit_hash
        entropicDiff['reason'] = "High Entropy"
    return entropicDiff

def regex_check(printableDiff, commit_time, branch_name, prev_commit, blob, commit_hash, regexes={}):
    secret_regexes = regexes
    regex_matches = []
    for key in secret_regexes:
        found_strings = secret_regexes[key].findall(printableDiff)
        for found_string in found_strings:
            found_diff = printableDiff.replace(printableDiff, bcolors.WARNING + found_string + bcolors.ENDC)
        if found_strings:
            foundRegex = {}
            foundRegex['date'] = commit_time
            foundRegex['path'] = blob.b_path if blob.b_path else blob.a_path
            foundRegex['branch'] = branch_name
            foundRegex['commit'] = prev_commit.message
            foundRegex['diff'] = blob.diff.decode('utf-8', errors='replace')
            foundRegex['stringsFound'] = found_strings
            foundRegex['printDiff'] = found_diff
            foundRegex['reason'] = key
            foundRegex['commitHash'] = commit_hash
            regex_matches.append(foundRegex)
    return regex_matches

def diff_worker(diff, curr_commit, prev_commit, branch_name, commit_hash, regexes, do_entropy, do_regex):
    issues = []
    for blob in diff:
        printableDiff = blob.diff.decode('utf-8', errors='replace')
        if printableDiff.startswith("Binary files"):
            continue
        commit_time =  datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
        found_issues = []
        if do_entropy:
            entropicDiff = find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob, commit_hash)
            if entropicDiff:
                found_issues.append(entropicDiff)
        if do_regex:
            found_regexes = regex_check(printableDiff, commit_time, branch_name, prev_commit, blob, commit_hash, regexes)
            found_issues += found_regexes
        issues += found_issues
    return issues

def find_strings(config):
    project_path = clone_git_repo(config.git_url)
    repo = Repo(project_path)
    already_searched = set()
    output_dir = tempfile.mkdtemp()

    found_issues = []
    for remote_branch in repo.remotes.origin.fetch():
        since_commit_reached = False
        branch_name = remote_branch.name.split('/')[1]
        try:
            repo.git.checkout(remote_branch, b=branch_name)
        except:
            pass

        prev_commit = None
        for curr_commit in repo.iter_commits(max_count=config.max_depth):
            commit_hash = curr_commit.hexsha
            if commit_hash == config.since_commit:
                since_commit_reached = True
            if config.since_commit and since_commit_reached:
                prev_commit = curr_commit
                continue
            # if not prev_commit, then curr_commit is the newest commit. And we have nothing to diff with.
            # But we will diff the first commit with NULL_TREE here to check the oldest code.
            # In this way, no commit will be missed.
            if not prev_commit:
                prev_commit = curr_commit
                continue
            else:
                diff = prev_commit.diff(curr_commit, create_patch=True)
            found_issues += diff_worker(diff, curr_commit, prev_commit, branch_name, commit_hash, config.regexes, config.do_entropy, config.do_regex)
            prev_commit = curr_commit
        # Handling the first commit
        diff = curr_commit.diff(NULL_TREE, create_patch=True)
        found_issues += diff_worker(diff, curr_commit, prev_commit, branch_name, commit_hash, config.regexes, config.do_entropy, config.do_regex)

    return found_issues

if __name__ == "__main__":
    main()
