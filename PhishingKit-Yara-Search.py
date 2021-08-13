#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# PhishingKit-Yara-Search - Yara scan Phishing Kit's Zip archive(s)
# Copyright (C) 2019 Thomas "tAd" Damonneville
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# pip3 install yara-python
import yara
import sys
import os
import argparse
from tools.confparser import ConfParser
VERSION = "0.3.0"


def banner():
    banner = '''
    ____  __ __  __  __                      _____                      __  
   / __ \/ // /  \ \/ /___ __________ _     / ___/___  ____ ___________/ /_ 
  / /_/ / //_/____\  / __ `/ ___/ __ `/_____\__ \/ _ \/ __ `/ ___/ ___/ __ \\
 / ____/ /\ \_____/ / /_/ / /  / /_/ /_____/__/ /  __/ /_/ / /  / /__/ / / /
/_/   /_/  \_\   /_/\__,_/_/   \__,_/     /____/\___/\__,_/_/   \___/_/ /_/ 
'''
    print(banner)
    print("-= PhishingKit Yara Search - Classify phishing kits zip files with Yara rules - v" + VERSION + " =-\n")


# Config file read
def ConfAnalysis(ConfFile):
    global yara_rules_dir
    global yara_compiled
    global archivesDir_to_analyse

    try:
        CONF = ConfParser(ConfFile)
        # Yara stuff
        yara_rules_dir = CONF.yara_rules_dir
        yara_compiled = CONF.yara_compiled
        # Path stuff
        archivesDir_to_analyse = CONF.archivesDir_to_analyse
    except Exception as e:
        print("[!!!] ConfParser Error: " + str(e))


# Tool options
def args_parse():
    global ConfFile
    global yara_compiled
    global yara_rules_dir
    global archivesDir_to_analyse
    global file_to_analyse
    global rule_to_use
    ConfFile = ""
    yara_rules_dir = ""
    archivesDir_to_analyse = ""
    rule_to_use = ""
    # Default yara rules compiled directory
    yara_compiled = "/tmp/yara_rules_compiled/"

    parser = argparse.ArgumentParser(description="Phishing kits Zip files Yara checker")
    parser.add_argument("-c", "--configuration", action="store", help="Configuration file to use")
    parser.add_argument("-f", "--file", help="File to check")
    parser.add_argument("-r", "--rule", help="Use specific Yara rule")
    parser.add_argument("-D", "--directory", help="Recursive search into directory")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbose")
    args = parser.parse_args()

    try:
        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(0)

        if args.configuration:
            if not os.path.isfile(args.configuration):
                print("The specified configuration file {} does not exist, exiting.".format(args.configuration))
                sys.exit(1)
            else:
                ConfFile = str(args.configuration)

        elif args.directory or args.file:
            if args.directory:
                if not os.path.exists(args.directory):
                    if args.file:
                        if not os.path.isfile(args.file):
                            print("The specified file {} does not exist, exiting.".format(args.file))
                            sys.exit(1)
                        file_to_analyse = args.file
                        if args.rule:
                            if os.path.isdir(args.rule):
                                print("Using all rules of directory: {}".format(args.rule))
                                yarlist = []
                                for yarfile in os.listdir(args.rule):
                                    if yarfile.endswith('yar'):
                                        yarlist.append(yarfile)
                                if not yarlist:
                                    print("The directory {} does not contain any yara rule, exiting.".format(args.rule))
                                    sys.exit(1)
                                else:
                                    rule_to_use = yarlist

                            elif not os.path.isfile(args.rule):
                                print("The specified rule {} does not exist, exiting.".format(args.rule))
                                sys.exit(1)
                            rule_to_use = args.rule

                    else:
                        print("The specified directory to analyse {} doesn't exist, skip".format(args.directory))
                        sys.exit(1)
                else:
                    archivesDir_to_analyse = args.directory
                    if args.rule:
                        if os.path.isdir(args.rule):
                            print("Using all rules of directory: {}".format(args.rule))
                            yarlist = []
                            for yarfile in os.listdir(args.rule):
                                if yarfile.endswith('yar'):
                                    yarlist.append(yarfile)
                            if not yarlist:
                                print("The directory {} does not contain any yara rule, exiting.".format(args.rule))
                                sys.exit(1)
                            else:
                                rule_to_use = yarlist

                        elif not os.path.isfile(args.rule):
                            print("The specified rule {} does not exist, exiting.".format(args.rule))
                            sys.exit(1)
                        rule_to_use = args.rule

            elif args.file:
                if not os.path.isfile(args.file):
                    print("The specified file {} does not exist, exiting.".format(args.file))
                    sys.exit(1)
                file_to_analyse = args.file
                if args.rule:
                    if os.path.isdir(args.rule):
                        print("Using all rules of directory: {}".format(args.rule))
                        yarlist = []
                        for yarfile in os.listdir(args.rule):
                            if yarfile.endswith('yar'):
                                yarlist.append(yarfile)
                        if not yarlist:
                            print("The directory {} does not contain any yara rule, exiting.".format(args.rule))
                            sys.exit(1)
                        else:
                            rule_to_use = yarlist

                    elif not os.path.isfile(args.rule):
                        print("The specified rule {} does not exist, exiting.".format(args.rule))
                        sys.exit(1)
                    rule_to_use = args.rule

    except Exception as e:
        print(e)


def main(ConfFile):
    global yara_rules_dir
    # Config
    if ConfFile:
        ConfAnalysis(ConfFile)
        # test if directories exists
        if not os.path.exists(yara_rules_dir):
            print("The specified rules directory {} doesn't exist, skip".format(yara_rules_dir))
            sys.exit(1)

        if not os.path.exists(yara_compiled):
            print("The specified compiled directory {} doesn't exist, trying to create it...".format(yara_compiled))
            try:
                os.makedirs(yara_compiled, mode=0o777, exist_ok=True)
                print("{} created.\n".format(yara_compiled))
            except Exception as e:
                print("[!!!] Directory creation Error: " + str(e))
                sys.exit(1)

        if not os.path.exists(archivesDir_to_analyse):
            print("The specified directory to analyse {} doesn't exist, skip".format(archivesDir_to_analyse))
            sys.exit(0)

    # test if directories exists
    elif yara_rules_dir and not os.path.exists(yara_rules_dir):
        print("The specified rules directory {} doesn't exist, skip".format(yara_rules_dir))
        sys.exit(1)

    elif not os.path.exists(yara_compiled):
        print("The specified compiled directory {} doesn't exist, trying to create it...".format(yara_compiled))
        try:
            os.makedirs(yara_compiled, mode=0o777, exist_ok=True)
            print("{} created.\n".format(yara_compiled))
        except Exception as e:
            print("[!!!] Directory creation Error: " + str(e))
            sys.exit(1)

    elif archivesDir_to_analyse and not os.path.exists(archivesDir_to_analyse):
        print("The specified directory to analyse {} doesn't exist, skip".format(archivesDir_to_analyse))
        sys.exit(0)

    elif rule_to_use and not yara_rules_dir:
        yara_rules_dir = rule_to_use

    # list .yar files
    yarfiles = []
    if rule_to_use:
        if os.path.isfile(rule_to_use):
            yarfiles.append(rule_to_use)
        if os.path.isdir(rule_to_use):
            for yarfile in os.listdir(rule_to_use):
                if yarfile.endswith('yar'):
                    yarfiles.append(yarfile)
    else:
        if not yara_rules_dir and rule_to_use:
            yara_rules_dir = os.path.dirname(rule_to_use)
        for yarfile in os.listdir(yara_rules_dir):
            if yarfile.endswith('yar'):
                yarfiles.append(yarfile)

                # if args.verbose == 2:
                #     print("the square of {} equals {}".format(args.square, answer))
                # elif args.verbose == 1:
                #     print("{}^2 == {}".format(args.square, answer))
                # else:
                #     print(answer)

    # compile and load YARA rules
    compiled_rules = []
    if not os.path.exists(yara_compiled):
        print("The specified compiled directory {} doesn't exist, trying to create it...".format(yara_compiled))
        try:
            os.makedirs(yara_compiled, mode=0o777, exist_ok=True)
            print("{} created.\n".format(yara_compiled))
        except Exception as e:
            print("[!!!] Directory creation Error: " + str(e))
            sys.exit(1)

    for f in yarfiles:
        try:
            if os.path.dirname(f):
                fi = os.path.basename(f)
                rules = yara.compile(f)
                rules.save(yara_compiled + fi)
                yara.load(yara_compiled + fi)
                compiled_rules.append(rules)
            else:
                rules = yara.compile(yara_rules_dir + f)
                rules.save(yara_compiled + f)
                yara.load(yara_compiled + f)
                compiled_rules.append(rules)

        except Exception as e:
            print(e)

    # test YARA rules on ZIP archives
    try:
        # create list of files to analyse
        zipfiles = []
        if archivesDir_to_analyse:
            for zipfile in os.listdir(archivesDir_to_analyse):
                if zipfile.endswith('zip'):
                    zipfiles.append(zipfile)
        elif file_to_analyse:
            zipfiles.append(file_to_analyse)
        # analyse files
        for f in zipfiles:
            global matching_rule
            matching_rule = []
            for rule in compiled_rules:
                matches = rule.match(archivesDir_to_analyse + f)
                if matches:
                    matching_rule.append(matches)
                else:
                    nomatch = rule
            if len(matching_rule) > 0:
                PrintMatching(f, matching_rule)
            elif rule_to_use:
                NoMatch(f, nomatch)
            else:
                # print("--> I need a rule: {}".format(f))
                pass

    except Exception as e:
        print(e)


def PrintMatching(package, *matching_rule):
    print("\tfile: {}".format(package))
    for m in matching_rule:
        print("\t\t--> This rule(s) matched: {}".format(m))
    pass


def NoMatch(package, *nomatch):
    for m in nomatch:
        # print("\tfile: {}".format(package))
        # print("\t\t--> no match")
        pass


# Start
if __name__ == '__main__':
    banner()
    args_parse()
    main(ConfFile)
