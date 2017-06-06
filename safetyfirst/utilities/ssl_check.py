#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

from safetyfirst.cli import SafetyFirstUtility


class SSLCheck(SafetyFirstUtility):
    """
    Get and Check SSL Information from CLI
    """
    description = 'Check the certificate of one or more hosts'

    def add_arguments(self):

        self.argparser.add_argument('-t', '--tls-ext-host-name', help='The TLS Extension Host Name', type=str)
        self.argparser.add_argument('hostname', help='The Hostname to check', type=str)

    def run(self):
        pass


def launch_new_instance():
    """
    Helper for launching

    :return:
    """
    utility = SSLCheck()
    utility.run()


if __name__ == '__main__':
    launch_new_instance()