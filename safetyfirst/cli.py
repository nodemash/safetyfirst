#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse


class SafetyFirstUtility(object):

    description = ''
    epilog = ''
    argparser = None
    args = None

    def __init__(self, args=None):
        """
        Perform argument processing and other setup for a SafetyFirstUtility.

        :param args:
        """
        self._init_common_parser()
        self.add_arguments()
        self.args = self.argparser.parse_args(args)

        # Ensure SIGPIPE doesn't throw an exception
        # Prevents [Errno 32] Broken pipe errors, e.g. when piping to 'head'
        # To test from the shell:
        #  python -c "for i in range(5000): print('a,b,c')" | csvlook | head
        # Without this fix you will see at the end:
        #  [Errno 32] Broken pipe
        # With this fix, there should be no error
        # For details on Python and SIGPIPE, see http://bugs.python.org/issue1652
        try:
            import signal
            signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        except (ImportError, AttributeError):
            # Do nothing on platforms that don't have signals or don't have SIGPIPE
            pass

    def add_arguments(self):
        """
        Called upon initialization once the parser for common arguments has been constructed.
        Should be overriden by individual utilities.

        :return:
        """
        raise NotImplementedError('add_arguments must be provided by each subclass of SafetyFirstUtility.')

    def _init_common_parser(self):
        """
        Prepare a base argparse argument parser so that flags are consistent across different shell command tools.
        If you want to constrain which common args are present, you can pass a string for 'omitflags'. Any argument
        whose single-letter form is contained in 'omitflags' will be left out of the configured parser. Use 'f' for
        file.

        :return:
        """
        self.argparser = argparse.ArgumentParser(description=self.description, epilog=self.epilog)

    def run(self):
        """
        Main loop of the utility.
        Should be overriden by individual utilities and explicitly called by the executing script.

        :return:
        """
        raise NotImplementedError(' must be provided by each subclass of SafetyFirstUtility.')