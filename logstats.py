#!/usr/bin/env python

import argparse
import re
import os
import math
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
        self.ip2cc = {}
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

    def _ip2cc(self, ip):
        if ip in self.ip2cc.keys():
            return self.ip2cc[ip]
        b_ip = struct.unpack('!L', socket.inet_pton(socket.AF_INET, ip))[0]
        for r in self.records:
            # calculate binary IP range
            cc = r[0]
            country_name = r[1]
            rirtype = r[5]
            if rirtype == 'ipv4':
                _, temp = r[2].split('/')
                cidr = int(temp)
                _32bits = long(math.pow(2, 32) - 1)
                b_mask = _32bits << (32 - cidr) & _32bits
                b_network = struct.unpack(
                    '!L',
                    socket.inet_pton(socket.AF_INET, r[3])
                )[0]
                b_broadcast = (b_network | ~b_mask) & _32bits
                if b_ip >= b_network and b_ip <= b_broadcast:
                    self.ip2cc[ip] = {'cc': cc, 'country_name': country_name}
                    return self.ip2cc[ip]
            else:
                continue

    def _iptables_log(self, options):
        f = open(options.iptables, 'r')
        data = f.read()
        f.close()
        total = 0
        for line in data.split('\n'):
            m = re.match(r'.+SRC=((\d{1,3}\.){3}\d{1,3})', line)
            if not m:
                continue
            elif self._RFC1918(m.group(1)):
                continue
            if m.group(1) not in self.freq:
                self.freq[m.group(1)] = 1
            else:
                self.freq[m.group(1)] += 1
            total += 1

        print """
 Top %d IPTABLES Firewall Drops by Source Address
------------------------------------------------------------------\
""" % (int(options.top))
        top = 0
        for r in sorted(self.freq, key=self.freq.__getitem__, reverse=True):
            if top > int(options.top):
                break
            ccd = self._ip2cc(r)
            percent = (float(self.freq[r]) / total) * 100.0
            print '%02d: %20s | %-15s | hits = %5d (%5.2f%%)' % \
                (top, ccd['country_name'], r, self.freq[r], percent)
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
        for row in cur.fetchall():
            self.records.append(row)

    def run(self, options):
        self._get_dbrecords(options)
        self._iptables_log(options)


if __name__ == '__main__':

    VERSION = '20150113_1033'
    desc = """
----------------------------------
 Version %s
 Author: Joff Thyer (c) 2015
 Black Hills Information Security
----------------------------------
""" % (VERSION)
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
        '--top', default=10, help='output top N countries'
    )
    options = parser.parse_args()

    logstats = RIRLogStats()
    logstats.run(options)
