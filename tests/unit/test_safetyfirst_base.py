#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tests import *
from tests.helpers import *

from safetyfirst.safetyfirst import SafetyFirst


class TestSafetyFirstBase(unittest.TestCase):

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

        # only use a subset of subjectAltName from the google cert, because there are too many
        expected_certificate_meta = {
            'end_date': '16.08.2017',
            'countryName': 'US',
            'organizationalUnitName': None,
            'emailAddress': None,
            'localityName': None,
            'issue_date': '24.05.2017',
            'issuer_x509': 'Google Internet Authority G2',
            'organizationName': 'Google Inc',
            'subjectAltName': expected_sub_alt_names,
            'commonName': '*.google.com',
            'stateOrProvinceName': None,
            'serial_number': 7087259811198802903
        }

        assert expected_certificate_meta == certificate_meta
