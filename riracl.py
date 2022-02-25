#!/usr/bin/env python3

import argparse
import os
import sys
import struct
import socket
import sqlite3


class RIRACL:

    def __init__(self):
        dbhome = '{}/.rirdb'.format(os.path.expanduser('~'))
        self.dbname = '{}/rir.db'.format(dbhome)
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
{}
AND (rir.status = 'assigned' or rir.status = 'allocated')
""".format(sql_type)

        if options.cc:
            sql += "AND rir.cc = '{}'".format(options.cc.upper())
        elif options.country:
            sql += "AND country_codes.name like '{}%'".format(options.country)
        sql += 'ORDER BY rir.cc, rir.type, rir.start_binary ASC'

        cur.execute(sql)
        for row in cur.fetchall():
            self.records.append(row)

    def _iplist(self, options):
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
                print('\n# {}: {}'.format(cc, country))
                lastcc = cc
            if options.ipv4 and rirtype == 'ipv4':
                print('{}'.format(cidr))
            if options.ipv6 and rirtype == 'ipv6':
                print('{}/{}'.format(start, value))

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
                print('\n# {}: {}'.format(cc, country))
                lastcc = cc
            if options.ipv4 and rirtype == 'ipv4':
                print('-A INPUT -p ip -s {} -j {}'.format\
                    (cidr, options.dropchain))
            if options.ipv6 and rirtype == 'ipv6':
                print('-A INPUT -p ipv6 -s {}/{} -j {}'.format\
                    (start, value, options.dropchain))

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
                objname = 'CountryCode:{}'.format(cc)
                objects.append(objname)
                print("""
! {}: {}
object-group network {}""".format(cc, country, objname))
                lastcc = cc

            if options.ipv4 and rirtype == 'ipv4':
                network, cidr = cidrnet.split('/')
                mask = self._cidr2mask(cidr)
                print('    network-object {} {}'.format(network, mask))
            if options.ipv6 and rirtype == 'ipv6':
                print('    network-object {}/{}'.format(start, value))

        print('!')
        for obj in objects:
            print("""\
access-list deny_country_ingress extended \
deny ip object-group {} any""".format(obj))

        for obj in objects:
            print("""\
access-list deny_country_egress extended \
deny ip any object-group {}""".format(obj))

    def _cisco_switch(self, options):
        if options.ipv4 and options.ipv6:
            print('ERROR: Cannot process both v4 and v6 ACLs')
            return
        lastcc = ''
        seq = 10
        for line in self.records:
            cc = line[0]
            country = line[1]
            if not country:
                country = '[Unknown ISO-3166 Country Code]'

            rirtype = line[5]
            proto = rirtype
            if proto == 'ipv4':
                proto = 'ip'

            if cc != lastcc:
                header = '\n! {}: {}'.format(cc, country)
                xt = ''
                if options.ipv4:
                    xt = 'extended '
                header += '\n{} access-list {}{}:{}_{}'.format\
                          (proto, xt, cc, country, rirtype)
                if lastcc != '':
                    if options.ipv6:
                        print('  seq {} permit {} any any'.format(seq, proto))
                    else:
                        print('  {} permit {} any any'.format(seq, proto))
                print('{}'.format(header))
                lastcc = cc
                seq = 10

            if options.ipv4 and rirtype == 'ipv4':
                network, cidr = line[2].split('/')
                revmask = self._cidr2revmask(cidr)
                print('  {} deny ip {} {} any'.format(seq, network, revmask))
                if options.bidir:
                    print('  {} deny ip any {} {}'.format\
                        (seq + 1, network, revmask))
            elif options.ipv6 and rirtype == 'ipv6':
                start = line[3]
                value = line[4]
                print('  seq {} deny ipv6 {}/{} any'.format(seq, start, value))
                if options.bidir:
                    print('  seq {} deny ipv6 any {}/{}'.format\
                        (seq + 1, start, value))
            seq += 10

        if options.ipv6:
            print('  seq {} permit {} any any'.format(seq, proto))
        else:
            print('  {} permit {} any any'.format(seq, proto))

    def _cisco_router(self, options):
        if options.ipv4 and options.ipv6:
            print('ERROR: Cannot process both v4 and v6 ACLs')
            return
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
                name = '{}:{}_{}'.format(cc, country, rirtype)
                lastcc = cc
                print('\n! prefix-list {}:{}'.format(cc, country))
            if options.ipv4 and rirtype == 'ipv4':
                network, cidr = line[2].split('/')
                print('ip prefix-list {} seq {} deny {}/{}'.format\
                    (name, seq, network, cidr))
            elif options.ipv6 and rirtype == 'ipv6':
                start = line[3]
                value = line[4]
                print('ipv6 prefix-list {} seq {} deny {}/{}'.format\
                    (name, seq, start, value))
            seq += 10

    def run(self, options):
        self._get_dbrecords(options)
        if options.iplist:
            self._iplist(options)
        if options.iptables:
            self._iptables(options)
        elif options.asa:
            self._asa(options)
        elif options.switch:
            self._cisco_switch(options)
        elif options.router:
            self._cisco_router(options)

if __name__ == '__main__':

    VERSION = '20150113_1033'
    desc = """
----------------------------------
 Version {}
 Author: Joff Thyer (c) 2015
 Black Hills Information Security
----------------------------------
""".format(VERSION)
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=desc
    )
    parser.add_argument(
        '--iplist', action='store_true',
        default=False,
        help='output iplist format')
    parser.add_argument(
        '--iptables', action='store_true',
        default=False,
        help='output iptables format'
    )
    parser.add_argument(
        '--dropchain',
        default='DROP',
        help='drop chain name for iptables'
    )
    parser.add_argument(
        '--ipv4', action='store_true',
        default=False,
        help='ipv4 addresses'
    )
    parser.add_argument(
        '--bidir', action='store_true',
        default=False,
        help='create bidirectional ACLs for switches'
    )
    parser.add_argument(
        '--ipv6', action='store_true',
        default=False,
        help='ipv6 addresses'
    )
    parser.add_argument(
        '--asa', action='store_true',
        default=False,
        help='output Cisco ASA format'
    )
    parser.add_argument(
        '--switch', action='store_true',
        default=False,
        help='output Cisco switch ACL format'
    )
    parser.add_argument(
        '--router', action='store_true',
        default=False,
        help='output Cisco router prefix list format'
    )
    parser.add_argument(
        '--country', help='search for a specific country name'
    )
    parser.add_argument(
        '--cc', help='search for a specific country code'
    )
    options = parser.parse_args()

    if not (options.ipv4 or options.ipv6):
        parser.print_help()
        print("""
ERROR: either --ipv4 or --ipv6 and an output format must be specified
""")
        sys.exit(1)
    elif not (options.iplist or options.iptables or options.asa or
              options.switch or options.router):
        parser.print_help()
        print("""
ERROR: please specify an output format (--iplist/--iptables/--asa/--switch/--router)
""")
        sys.exit(1)

    riracl = RIRACL()
    riracl.run(options)
