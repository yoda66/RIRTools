#!/usr/bin/env python

import argparse
import os
import sys
import struct
import socket
import csv
import re
import hashlib
import math
import urllib2
import sqlite3
from datetime import datetime, timedelta


class RIRACL:

    def __init__(self):
        dbhome = '%s/.rirdb' % (os.path.expanduser('~'))
        self.dbname = '%s/rir.db' % (dbhome)
        self.dbh = sqlite3.connect(self.dbname)
        self.records = []

    def _cidr2mask(self, cidr):
        b_mask = (0xffffffff00000000 >> int(cidr)) & 0xffffffff
        return socket.inet_ntoa(struct.pack('!L', b_mask))

    def _get_dbrecords(self, options):
        cur = self.dbh.cursor()
        if options.ipv4 and not options.ipv6:
            sql_type = "WHERE rir.type = 'ipv4'"
        elif not options.ipv4 and options.ipv6:
            sql_type = "WHERE rir.type = 'ipv6'"
        elif options.ipv4 and options.ipv6:
            sql_type = "WHERE (rir.type = 'ipv4' OR rir.type = 'ipv6')"

        sql = """\
SELECT  rir.cc, country_codes.name,
        rir.cidr, rir.start, rir.value, rir.type
FROM rir
LEFT JOIN country_codes
ON country_codes.cc = rir.cc
%s
AND (rir.status = 'assigned' or rir.status = 'allocated')
""" % (sql_type)

        if options.cc:
            sql += "AND rir.cc = '%s'" % (options.cc.upper())
        elif options.country:
            sql += "AND country_codes.name like '%s%%'" % (options.country)
        sql += 'ORDER BY rir.cc, rir.type, rir.start_binary ASC'

        cur.execute(sql)
        for row in cur.fetchall():
            self.records.append(row)

    def _iptables(self, options):
        lastcc = ''
        for line in self.records:
            cc = line[0]
            country = line[1]
            if not country:
                country = '[Unknown ISO-3166 Country Code]'
            cidr = line[2]
            start = line[3]
            value = line[4]
            rirtype = line[5]
            if cc != lastcc:
                print '\n# %s: %s' % (cc, country)
                lastcc = cc
            if options.ipv4 and rirtype == 'ipv4':
                print '-A INPUT -p ip -s %s -j DROP' % (cidr)
            if options.ipv6 and rirtype == 'ipv6':
                print '-A INPUT -p ipv6 -s %s/%s -j DROP' % (start, value)

    def _asa(self, options):
        lastcc = ''
        objects = []
        print '! -- BEGIN --'
        for line in self.records:
            cc = line[0]
            country = line[1]
            if not country:
                country = '[Unknown ISO-3166 Country Code]'
            cidrnet = line[2]
            start = line[3]
            value = line[4]
            rirtype = line[5]
            if cc != lastcc:
                objname = 'CountryCode:%s' % (cc)
                objects.append(objname)
                print """
! %s: %s
object-group network %s""" % (cc, country, objname)
                lastcc = cc

            if options.ipv4 and rirtype == 'ipv4':
                network, cidr = cidrnet.split('/')
                mask = self._cidr2mask(cidr)
                print '    network-object %s %s' % (network, mask)
            if options.ipv6 and rirtype == 'ipv6':
                print '    network-object %s/%s' % (start, value)

        print '!'
        for obj in objects:
            print """\
access-list deny_country_ingress extended \
deny ip object-group %s any""" % (obj)

        for obj in objects:
            print """\
access-list deny_country_egress extended \
deny ip any object-group %s""" % (obj)
        print '! -- END --'

    def run(self, options):
        self._get_dbrecords(options)
        if options.iptables:
            self._iptables(options)
        if options.asa:
            self._asa(options)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--iptables', action='store_true',
        default=False,
        help='produce IP tables output')
    parser.add_argument(
        '--ipv4', action='store_true',
        default=False,
        help='ipv4 only')
    parser.add_argument(
        '--ipv6', action='store_true',
        default=False,
        help='ipv6 only')
    parser.add_argument(
        '--asa', action='store_true',
        default=False,
        help='produce Cisco ASA output')
    parser.add_argument(
        '--country', help='specify country to produce output for'
    )
    parser.add_argument(
        '--cc', help='specify a country code to produce output for'
    )
    options = parser.parse_args()
    riracl = RIRACL()
    if options:
        riracl.run(options)
