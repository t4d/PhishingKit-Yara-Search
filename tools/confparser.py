#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import configparser


class ConfParser:
    '''Configuration file parser'''
    def __init__(self, Confile=None):
        try:
            self.config = configparser.ConfigParser()

            with open(Confile, 'r', encoding='utf-8') as f:
                self.config.readfp(f)

                # Yara directories
                self.yara_rules_dir = self.config['YARA']['yara_rules_dir']
                self.yara_compiled = self.config['YARA']['yara_compiled']

                # Default Directory to scan
                self.archivesDir_to_analyse = self.config['SCAN']['archivesDir_to_analyse']

        except IOError:
            print("[!!!] Configuration file Error: " + Confile)

        except Exception as e:
            print("[!!!] ConfParser Error: " + str(e))
