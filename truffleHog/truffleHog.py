#!/usr/bin/env python
# -*- coding: utf-8 -*-

import math
import datetime
import argparse
import tempfile
import os
import re
import json
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
    parser.add_argument("--json", dest="output_json", action="store_true", help="Output in JSON", default=False)
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
    output_results(results, config)

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

def output_results(results, config):
    if config.output_json:
        print(json.dumps(results, sort_keys=True))
        return

    for issue in results:
        print_issue(issue)

def mark_strings(diff, strings_found):
    for found_string in strings_found:
        diff = diff.replace(found_string, bcolors.WARNING + found_string + bcolors.ENDC)
    return diff

def print_issue(issue, print_diff):
    print("~~~~~~~~~~~~~~~~~~~~~")
    print("{}Reason: {}{}".format(bcolors.OKGREEN, issue['reason'], bcolors.ENDC))
    print("{}Date: {}{}".format(bcolors.OKGREEN, issue['date'], bcolors.ENDC))
    print("{}Hash: {}{}".format(bcolors.OKGREEN, issue['commitHash'], bcolors.ENDC))
    print("{}Filepath: {}{}".format(bcolors.OKGREEN, issue['path'], bcolors.ENDC))
    print("{}Branch: {}{}".format(bcolors.OKGREEN, issue['branch'], bcolors.ENDC))
    print("{}Commit: {}{}".format(bcolors.OKGREEN, issue['commit'], bcolors.ENDC))
    print(mark_strings(issue['diff'], issue['stringsFound']))
    print("~~~~~~~~~~~~~~~~~~~~~")


def find_entropy(diff, issue_zigote, commit_hash):
    strings_found = []
    lines = diff.split("\n")
    for line in lines:
        for word in line.split():
            for string in get_strings_of_set(word, BASE64_CHARS):
                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                if b64Entropy > 4.5:
                    strings_found.append(string)

            for string in get_strings_of_set(word, HEX_CHARS):
                hexEntropy = shannon_entropy(string, HEX_CHARS)
                if hexEntropy > 3:
                    strings_found.append(string)

    entropic_diff = None
    if strings_found:
        entropic_diff = dict(issue_zigote) # make a copy
        entropic_diff['stringsFound'] = strings_found
        entropic_diff['reason'] = "High Entropy"
    return entropic_diff

def regex_check(diff, issue_zigote, regexes):
    regex_matches = []
    for key in regexes:
        strings_found = regexes[key].findall(diff)
        if strings_found:
            regex_match = dict(issue_zigote) # make a copy
            regex_match['stringsFound'] = strings_found
            regex_match['reason'] = key
            regex_matches.append(regex_match)
    return regex_matches

def diff_worker(diff, curr_commit, prev_commit, branch_name, commit_hash, config):
    issues = []
    for blob in diff:
        blob_diff = blob.diff.decode('utf-8', errors='replace')
        if blob_diff.startswith("Binary files"):
            continue

        issue_zigote = {
            "date": datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S'),
            "path": blob.b_path if blob.b_path else blob.a_path,
            "branch": branch_name,
            "commit": prev_commit.message,
            "diff": blob_diff,
            "commitHash": commit_hash
        }

        if config.do_entropy:
            entropic_diff = find_entropy(blob_diff, issue_zigote)
            if entropic_diff:
                issues.append(entropic_diff)

        if config.do_regex:
            issues += regex_check(blob_diff, issue_zigote, config.regexes)

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
            found_issues += diff_worker(diff, curr_commit, prev_commit, branch_name, commit_hash, config)
            prev_commit = curr_commit
        # Handling the first commit
        diff = curr_commit.diff(NULL_TREE, create_patch=True)
        found_issues += diff_worker(diff, curr_commit, prev_commit, branch_name, commit_hash, config)

    return found_issues

if __name__ == "__main__":
    main()
