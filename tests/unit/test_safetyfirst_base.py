#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Futures => UTF-8/Unicode
from __future__ import unicode_literals
from __future__ import absolute_import

import pytest

from tests import *
from tests.helpers import *

from safetyfirst.safetyfirst import SafetyFirst
from safetyfirst.exceptions import (
    HostnameWrongError
)


class TestSafetyFirstBase(unittest.TestCase):

    def test_get_peer_certificat_wrong_host_false(self):

        with pytest.raises(HostnameWrongError):
            safety = SafetyFirst()
            peer_certificate = safety.get_peer_certificate(host='google..com')

    def test_get_peer_certificat_wrong_ip_false(self):
        safety = SafetyFirst()
        peer_certificate = safety.get_peer_certificate(host='127.0.0..1')

    def test_get_peer_certificat_wrong_ip_false(self):
        safety = SafetyFirst()
        peer_certificate = safety.get_peer_certificate(host='127.0.0.9')

    def test_get_peer_certificate(self):

        safety = SafetyFirst()
        peer_certificate = safety.get_peer_certificate(host='google.com')

        peer_certificate_issuer_data = {}

        for component in peer_certificate.get_issuer().get_components():
            peer_certificate_issuer_data[component[0]] = component[1]

        expected_peer_certificate_data = {
            'C': 'US',
            'CN': 'Google Internet Authority G2',
            'O': 'Google Inc'
        }

        assert expected_peer_certificate_data == peer_certificate_issuer_data

    def test_get_peer_certificate_sni(self):
        safety = SafetyFirst()

        peer_certificate = safety.get_peer_certificate(
            host='web01.nodemash.net',
            tlsext_host_name='www.nodemash.com'
        )

        peer_certificate_issuer_data = {}

        for component in peer_certificate.get_issuer().get_components():
            peer_certificate_issuer_data[component[0]] = component[1]

        expected_peer_certificate_data = {
            'C': 'US',
            'CN': 'Let\'s Encrypt Authority X3',
            'O': 'Let\'s Encrypt'
        }

        assert expected_peer_certificate_data == peer_certificate_issuer_data

    def test_get_certificate_meta(self):

        safety = SafetyFirst()
        peer_certificate = safety.get_peer_certificate(host='google.com')

        certificate_meta = safety.get_certificate_meta(peer_certificate)

        # expected alt names
        expected_sub_alt_names = [
            '*.google.com',
            '*.android.com'
        ]

        # remove all subjectAltName except *.google.com and *.android.com
        certificate_meta['subjectAltName'] = list(set(certificate_meta['subjectAltName']) & set(expected_sub_alt_names))

        # remove some keys since google changes it always
        certificate_meta.pop('end_date', None)
        certificate_meta.pop('issue_date', None)
        certificate_meta.pop('serial_number', None)

        # only use a subset of subjectAltName from the google cert, because there are too many
        expected_certificate_meta = {
            'countryName': 'US',
            'organizationalUnitName': None,
            'emailAddress': None,
            'localityName': None,
            'issuer_x509': 'Google Internet Authority G2',
            'organizationName': 'Google Inc',
            'subjectAltName': expected_sub_alt_names,
            'commonName': '*.google.com',
            'stateOrProvinceName': None
        }

        assert expected_certificate_meta == certificate_meta

    def test_certificate_serial_number(self):

        safety = SafetyFirst()
        peer_certificate = safety.get_peer_certificate(host='google.com')

        certificate_meta = safety.get_certificate_meta(peer_certificate)

        assert ('serial_number' in certificate_meta.keys() and isinstance(certificate_meta['serial_number'], int))

    def test_is_valid_hostname_true(self):

        safety = SafetyFirst()

        assert safety.is_valid_hostname('nodemash.com')

    def test_is_valid_hostname_false(self):

        safety = SafetyFirst()

        assert not safety.is_valid_hostname('nodemash...com')
