#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
The safetyfirst base module
"""
# Futures => UTF-8/Unicode
from __future__ import unicode_literals
from __future__ import absolute_import

import ssl
import pytz
import OpenSSL
import socket
import re

from datetime import datetime
from ndg.httpsclient.subj_alt_name import SubjectAltName as BaseSubjectAltName
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.type import univ, constraint
import pyasn1

from safetyfirst.exceptions import HostnameWrongError

# Note: This is a slightly bug-fixed version of same from ndg-httpsclient.
class SubjectAltName(BaseSubjectAltName):
    """
    ASN.1 implementation for subjectAltNames support

    Source: https://github.com/requests/requests-docs-it/blob/master/requests/packages/urllib3/contrib/pyopenssl.py
    """

    # There is no limit to how many SAN certificates a certificate may have,
    #   however this needs to have some limit so we'll set an arbitrarily high
    #   limit.
    sizeSpec = univ.SequenceOf.sizeSpec + \
        constraint.ValueSizeConstraint(1, 1024)


class SafetyFirst(object):
    """
    The main class of SafetyFirst
    """

    DEFAULT_SUBJECT_ALTERNATE_NAME = 'subjectAltName'
    SSL_DEFAULT_METHOD = ssl.PROTOCOL_TLSv1_2

    def __init__(self, ssl_method=None):
        """
        Init of SafetyFirst

        :param ssl_method: One of ssl.PROTOCOL_SSLv2, ssl.PROTOCOL_SSLv3, ssl.PROTOCOL_SSLv23, ssl.PROTOCOL_TLS,
        ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1 or, ssl.PROTOCOL_TLSv1_2
        """

        if ssl_method:
            self.SSL_DEFAULT_METHOD = ssl_method

    def is_valid_hostname(self, hostname):
        """
        check if we have a valid hostname

        :param hostname:
        :return:
        """

        if hostname[-1] == ".":
            # strip exactly one dot from the right, if present
            hostname = hostname[:-1]

        if len(hostname) > 253:
            return False

        labels = hostname.split(".")

        # the TLD must be not all-numeric
        if re.match(r"[0-9]+$", labels[-1]):
            return False

        allowed = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(label) for label in labels)

    def get_subj_alt_name(self, peer_cert):
        """
        Copied from ndg.httpsclient.ssl_peer_verification.ServerSSLCertVerification
        Extract subjectAltName DNS name settings from certificate extensions
        @param peer_cert: str, peer certificate in SSL connection.  subjectAltName settings if
        any will be extracted from this
        @type peer_cert:

        :param peer_cert:
        :rtype: OpenSSL.crypto.X509
        """
        # Search through extensions
        dns_name = []
        general_names = SubjectAltName()

        for i in range(peer_cert.get_extension_count()):
            ext = peer_cert.get_extension(i)
            ext_name = ext.get_short_name()

            if ext_name == self.DEFAULT_SUBJECT_ALTERNATE_NAME:

                # PyOpenSSL returns extension data in ASN.1 encoded form
                ext_dat = ext.get_data()
                decoded_dat = der_decoder.decode(ext_dat, asn1Spec=general_names)

                for name in decoded_dat:

                    if not isinstance(name, SubjectAltName):
                        continue
                    for entry in range(len(name)):
                        component = name.getComponentByPosition(entry)
                        if component.getName() != 'dNSName':
                            continue

                        dns_name.append(str(component.getComponent()))

        return dns_name

    def get_peer_certificate(self, host, tlsext_host_name=''):
        """
        Gets the certificate from a given host

        :param host: str, A remote address or host name
        :param tlsext_host_name: str, the host name for SNI
        :param timeout: int timeout for connecting to a host
        :return:
        """

        # build the connection
        ctx = OpenSSL.SSL.Context(method=self.SSL_DEFAULT_METHOD)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            s.connect((host, 443))

        except UnicodeError:
            raise HostnameWrongError('The given hostname: {} is wrong'.format(str(host)))

        cnx = OpenSSL.SSL.Connection(ctx, s)

        # tlsext_host_name can be different to the connecting host
        if tlsext_host_name:
            cnx.set_tlsext_host_name(bytes(tlsext_host_name))
        else:
            cnx.set_tlsext_host_name(bytes(host))

        cnx.set_connect_state()
        cnx.do_handshake()

        x509 = cnx.get_peer_certificate()
        s.close()

        return x509

    def get_certificate_meta(self, x509_certificate):
        """
        Reads the meta data from a given certificate

        :param x509_certificate: OpenSSL.crypto.X509, The Certificate
        :return: dict
        """

        # get issuer details
        issuer_data = x509_certificate.get_issuer()

        issuer_x509 = issuer_data.commonName
        organization_name = issuer_data.organizationName
        organizational_unit_name = issuer_data.organizationalUnitName
        locality_name = issuer_data.localityName
        state_or_province_name = issuer_data.stateOrProvinceName
        country_name = issuer_data.countryName
        email_address = issuer_data.emailAddress
        serial_number = x509_certificate.get_serial_number()

        server_name = x509_certificate.get_subject().commonName

        try:
            subject_alt_names = self.get_subj_alt_name(x509_certificate)

        except pyasn1.error.PyAsn1Error as ex:
            subject_alt_names = []

        # get the dates
        issue_date = datetime.strptime(x509_certificate.get_notBefore(), "%Y%m%d%H%M%SZ").replace(tzinfo=pytz.UTC)
        end_date = datetime.strptime(x509_certificate.get_notAfter(), "%Y%m%d%H%M%SZ").replace(tzinfo=pytz.UTC)

        certificate_meta_data = {
            'issuer_x509': issuer_x509,
            'commonName': server_name,
            'organizationName': organization_name,
            'organizationalUnitName': organizational_unit_name,
            'localityName': locality_name,
            'stateOrProvinceName': state_or_province_name,
            'countryName': country_name,
            'emailAddress': email_address,
            'issue_date': issue_date.strftime("%d.%m.%Y"),
            'end_date': end_date.strftime("%d.%m.%Y"),
            'subjectAltName': subject_alt_names,
            'serial_number': serial_number
        }

        return certificate_meta_data
