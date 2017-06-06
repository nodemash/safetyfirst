#!/usr/bin/env python
# -*- coding: utf-8 -*-

class CustomException(Exception):
    """
    A base exception that handles pretty-printing errors for command-line tools.
    """

    def __init__(self, msg):
        self.msg = msg

    def __unicode__(self):
        return self.msg

    def __str__(self):
        return self.msg
