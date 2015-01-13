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

    def _cidr2revmask(self, cidr):
        b_mask = ~(0xffffffff00000000 >> int(cidr)) & 0xffffffff
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

    def _cisco_switch(self, options):
        lastcc = ''
        for line in self.records:
            cc = line[0]
            country = line[1]
            if not country:
                country = '[Unknown ISO-3166 Country Code]'
            rirtype = line[5]
            if cc != lastcc:
                header = '! %s: %s' % (cc, country)
                if options.ipv4:
                    header += '\nip access-list extended %s:%s' % \
                        (cc, country)
                elif options.ipv6:
                    header += '\nipv6 access-list %s:%s' % (cc, country)
                print '%s' % (header)
                lastcc = cc
            if options.ipv4 and rirtype == 'ipv4':
                network, cidr = line[2].split('/')
                revmask = self._cidr2revmask(cidr)
                print '  deny ip %s %s any' % (network, revmask)
            if options.ipv6 and rirtype == 'ipv6':
                start = line[3]
                value = line[4]
                print '  deny ip %s/%s any' % (start, value)

    def _cisco_router(self, options):
        lastcc = ''
        seq = 10
        for line in self.records:
            cc = line[0]
            country = line[1]
            if not country:
                country = '[Unknown ISO-3166 Country Code]'
            rirtype = line[5]
            if cc != lastcc:
                seq = 10
                name = '%s:%s' % (cc, country)
                lastcc = cc
                print '\n! prefix-list %s:%s' % (cc, country)
            if options.ipv4 and rirtype == 'ipv4':
                network, cidr = line[2].split('/')
                print 'ip prefix-list %s seq %d deny %s/%s' % \
                    (name, seq, network, cidr)
            if options.ipv6 and rirtype == 'ipv6':
                start = line[3]
                value = line[4]
                print 'ipv6 prefix-list %s seq %d deny %s/%s' % \
                    (name, seq, start, value)
            seq += 10

    def run(self, options):
        self._get_dbrecords(options)
        if options.iptables:
            self._iptables(options)
        elif options.asa:
            self._asa(options)
        elif options.switch:
            self._cisco_switch(options)
        elif options.router:
            self._cisco_router(options)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--iptables', action='store_true',
        default=False,
        help='output iptables format')
    parser.add_argument(
        '--ipv4', action='store_true',
        default=False,
        help='ipv4 addresses')
    parser.add_argument(
        '--ipv6', action='store_true',
        default=False,
        help='ipv6 addresses')
    parser.add_argument(
        '--asa', action='store_true',
        default=False,
        help='output Cisco ASA format')
    parser.add_argument(
        '--switch', action='store_true',
        default=False,
        help='output Cisco switch ACL format')
    parser.add_argument(
        '--router', action='store_true',
        default=False,
        help='output Cisco router prefix list format')
    parser.add_argument(
        '--country', help='search for a specific country name'
    )
    parser.add_argument(
        '--cc', help='search for a specific country code'
    )
    options = parser.parse_args()
    if not (options.ipv4 or options.ipv6):
        parser.print_help()
        print '\r\nERROR: either --ipv4 or --ipv6 and an output format must be specified'
        sys.exit(1)
    elif not (options.iptables or options.asa or options.switch or options.router):
        parser.print_help()
        print '\r\nERROR: please specify an output format (--iptables/--asa/--switch/--router)'
        sys.exit(1)
        
    riracl = RIRACL()
    riracl.run(options)
