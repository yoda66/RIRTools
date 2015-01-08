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
        self.ipv4 = []

    def _cidr2mask(self, cidr):
        b_mask = (0xffffffff00000000 >> int(cidr)) & 0xffffffff
        return socket.inet_ntoa(struct.pack('!L', b_mask))

    def _get_ipv4_cidr(self, country=None):
        cur = self.dbh.cursor()
        sql = """\
SELECT  country_codes.cc,
        country_codes.name, rir.cidr
FROM rir
LEFT JOIN country_codes
ON country_codes.cc = rir.cc
WHERE rir.type = 'ipv4'
AND (rir.status = 'assigned' or rir.status = 'allocated')
"""
        if country:
            sql += "AND country_codes.name like '%s%%'" % (country)

        sql += """
ORDER BY country_codes.cc, rir.start_binary ASC"""

        cur.execute(sql)
        for row in cur.fetchall():
            self.ipv4.append(row)

    def _ipv4_iptables(self):
        lastcc = ''
        for line in self.ipv4:
            cc = line[0]
            country = line[1]
            cidr = line[2]
            if cc != lastcc:
                print '\n# %s: %s' % (cc, country)
                lastcc = cc
            print '-A INPUT -p ip -s %s -j DROP' % (cidr)

    def _ipv4_asa(self):
        lastcc = ''
        objects = []
        for line in self.ipv4:
            cc = line[0]
            country = line[1]
            cidrnet = line[2]
            network, cidr = cidrnet.split('/')
            mask = self._cidr2mask(cidr)
            if cc != lastcc:
                objname = 'CountryCode:%s' % (cc)
                objects.append(objname)
                print """
! %s: %s
object-group network %s""" % (cc, country, objname)
                lastcc = cc
            print '    network-object %s %s' % (network, mask)

        print '!\n!'
        for obj in objects:
            print """\
access-list deny_country_ingress extended \
deny ip object-group %s any""" % (obj)

        print '!\n!'
        for obj in objects:
            print """\
access-list deny_country_egress extended \
deny ip any object-group %s""" % (obj)

    def run(self, options):
        self._get_ipv4_cidr(country=options.country)
        if options.iptables:
            self._ipv4_iptables()
        if options.asa:
            self._ipv4_asa()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--iptables', action='store_true',
        default=False,
        help='produce IP tables output')
    parser.add_argument(
        '--asa', action='store_true',
        default=False,
        help='produce Cisco ASA output')
    parser.add_argument(
        '--country', help='specify country to produce output for'
    )
    options = parser.parse_args()
    riracl = RIRACL()
    riracl.run(options)
