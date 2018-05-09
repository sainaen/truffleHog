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
            label: re.compile(regex, re.IGNORECASE)
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

UNWORTHY_FILES = [
    "package.json",
    "yarn.lock",
    "Pipfile.lock",
    ".svg",
    ".css",
    ".js.map",
]

def is_worthy_diff(file_diff):
    """Decides if the given diff is worth looking at."""

    # skip binary files
    if file_diff.diff.decode('utf-8', errors='replace').startswith("Binary files"):
        return False

    path = file_diff.b_path if file_diff.b_path else file_diff.a_path
    for unworthy in UNWORTHY_FILES:
        if path.endswith(unworthy):
            return False

    return True

import sys

def diff_worker(diffs, commit, branch_name, config):
    issues = []
    for file_diff in diffs:
        if not is_worthy_diff(file_diff):
            continue

        patch = file_diff.diff.decode('utf-8', errors='replace')
        issue_zigote = {
            "date": commit.committed_datetime.strftime('%Y-%m-%d %H:%M:%S'),
            "timestamp": commit.committed_date,
            "path": file_diff.b_path if file_diff.b_path else file_diff.a_path,
            "branch": branch_name,
            "commit": commit.message,
            "diff": patch,
            "commitHash": commit.hexsha
        }

        if config.do_entropy:
            found_issue = find_entropy(patch, issue_zigote)
            if found_issue:
                issues.append(found_issue)

        if config.do_regex:
            issues += regex_check(patch, issue_zigote, config.regexes)

    return issues

def scan_branch(repo, ref, commits_seen, config):
    found_issues = []
    since_commit_reached = False
    branch_name = ref.name

    for commit in repo.iter_commits(rev=ref.commit, max_count=config.max_depth):
        if len(commit.parents) > 1:
            # skip merges
            continue

        base = commit.parents[0] if commit.parents else NULL_TREE
        base_hash = 'null' if base == NULL_TREE else base.hexsha
        diff_hash = "{}-{}".format(base_hash, commit.hexsha)
        if diff_hash in commits_seen:
            # no reason to continue since we reached the part
            # of the history that was already explored
            return found_issues

        if base == NULL_TREE:
            # when it’s the last commit, we need to handle it differently
            # since NULL_TREE doesn’t have a diff() method
            diff = commit.diff(base, create_patch=True)
        else:
            diff = base.diff(commit, create_patch=True)

        found_issues += diff_worker(diff, commit, branch_name, config)
        commits_seen.add(diff_hash)

        if config.since_commit == base_hash:
            # reached the end
            return found_issues

    return found_issues

def find_strings(config):
    if os.path.isdir(config.git_url):
        repo = Repo(config.git_url)
    else:
        repo = Repo.clone_from(config.git_url, tempfile.mkdtemp())

    found_issues = []
    commits_seen = set()
    for ref in repo.refs:
        found_issues += scan_branch(repo, ref, commits_seen, config)

    return found_issues

if __name__ == "__main__":
    main()
