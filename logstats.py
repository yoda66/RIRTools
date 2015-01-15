#!/usr/bin/env python

import argparse
import radix
import sys
import re
import os
import struct
import socket
import sqlite3


class RIRLogStats:

    def __init__(self):
        dbhome = '%s/.rirdb' % (os.path.expanduser('~'))
        self.dbname = '%s/rir.db' % (dbhome)
        self.dbh = sqlite3.connect(self.dbname)
        self.dbh.text_factory = str
        self.records = []
        self.rib = radix.Radix()
        self.country = {}
        self.freq = {}

    def _cidr2mask(self, cidr):
        b_mask = (0xffffffff00000000 >> int(cidr)) & 0xffffffff
        return socket.inet_ntoa(struct.pack('!L', b_mask))

    def _cidr2revmask(self, cidr):
        b_mask = ~(0xffffffff00000000 >> int(cidr)) & 0xffffffff
        return socket.inet_ntoa(struct.pack('!L', b_mask))

    def _RFC1918(self, ip):
        rfc1918 = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
        for n in rfc1918:
            rfc1918net, cidr = n.split('/')
            b_mask = (0xffffffff00000000 >> int(cidr)) & 0xffffffff
            b_network = struct.unpack('!L', socket.inet_aton(ip))[0] & b_mask
            network = socket.inet_ntoa(struct.pack('!L', b_network))
            if network == rfc1918net:
                return True
        return False

    def _iptables_log(self, options):
        f = open(options.iptables, 'r')
        data = f.read()
        f.close()

        if options.ipv4:
            if options.src:
                rxp = r'.+SRC=((\d{1,3}\.){3}\d{1,3})'
            elif options.dst:
                rxp = r'.+DST=((\d{1,3}\.){3}\d{1,3})'
        elif options.ipv6:
            if options.src:
                rxp = r'.+SRC=((\d{4}:){7}\d{4})'
            elif options.dst:
                rxp = r'.+DST=((\d{4}:){7}\d{4})'

        total = 0
        for line in data.split('\n'):
            m = re.match(rxp, line)
            if not m:
                continue
            elif self._RFC1918(m.group(1)):
                continue
            rib_entry = self.rib.search_best(m.group(1))
            if rib_entry:
                cc = rib_entry.data['cc']
                if cc not in self.freq:
                    self.freq[cc] = 1
                else:
                    self.freq[cc] += 1
                total += 1

        print """
 Top %d IPTABLES Firewall Hits by Source Country
------------------------------------------------------------------\
""" % (int(options.top))
        top = 1
        for r in sorted(self.freq, key=self.freq.__getitem__, reverse=True):
            if top > int(options.top):
                break
            percent = (float(self.freq[r]) / total) * 100.0
            print '%02d: %30s | hits = %6d (%5.2f%%)' % \
                (top, self.country[r], self.freq[r], percent)
            top += 1
        print """\
------------------------------------------------------------------"""

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
ORDER BY rir.cc, rir.type, rir.start_binary ASC
""" % (sql_type)
        cur.execute(sql)
        for r in cur.fetchall():
            cc = r[0]
            country_name = r[1]
            rirtype = r[5]
            if rirtype == 'ipv4':
                rnode = self.rib.add(r[2])
            elif rirtype == 'ipv6':
                rnode = self.rib.add('%s/%s' % (r[3], r[4]))
            else:
                continue
            if cc not in self.country:
                self.country[cc] = country_name
            rnode.data['cc'] = cc
            rnode.data['country_name'] = country_name

    def run(self, options):
        self._get_dbrecords(options)
        if options.iptables:
            self._iptables_log(options)


if __name__ == '__main__':

    VERSION = '20150114_1132'
    desc = """
----------------------------------
 %s version %s
 Author: Joff Thyer (c) 2015
 Black Hills Information Security
----------------------------------
""" % (os.path.basename(sys.argv[0]), VERSION)
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=desc
    )
    parser.add_argument(
        '--iptables', help='specify iptables logfile'
    )
    parser.add_argument(
        '--ipv4', action='store_true',
        default=False, help='ipv4 addresses'
    )
    parser.add_argument(
        '--ipv6', action='store_true',
        default=False, help='ipv4 addresses'
    )
    parser.add_argument(
        '--src', action='store_true',
        default=False, help='search for source addresses (default)'
    )
    parser.add_argument(
        '--dst', action='store_true',
        default=False, help='search for destination addresses'
    )
    parser.add_argument(
        '--top', default=10, help='output top N countries'
    )
    options = parser.parse_args()

    if not (options.ipv4 or options.iptables):
        parser.print_help()
        print '\nERROR: Please specify the --ipv4 flag and a log format'
        sys.exit(1)

    if not (options.src or options.dst):
        options.src = True

    print '%s' % (desc)
    logstats = RIRLogStats()
    logstats.run(options)
