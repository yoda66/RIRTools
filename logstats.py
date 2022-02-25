#!/usr/bin/env python3

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
        dbhome = '{}/.rirdb'.format(os.path.expanduser('~'))
        self.dbname = '{}/rir.db'.format(dbhome)
        self.dbh = sqlite3.connect(self.dbname)
        self.dbh.text_factory = str
        self.records = []
        self.rib = radix.Radix()
        self.country = {}
        self.freq = {}

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

    def _update_freq(self, ip):
        rib_entry = self.rib.search_best(ip)
        if not rib_entry:
            return 0
        cc = rib_entry.data['cc']
        if cc not in self.freq:
            self.freq[cc] = 1
        else:
            self.freq[cc] += 1
        return 1

    def _print_freq_summary(self, title, total):
        if str(options.top).lower() == "all":
            header = '\nAll {} Firewall Hits by Source Country\n'.format(title)
        else:
            header = '\n Top {:d} {} Firewall Hits by Source Country\n'.format(
                int(options.top), title)
        print(header)

        top = 1
        for r in sorted(self.freq, key=self.freq.__getitem__, reverse=True):
            if str(options.top).lower() != "all":
                if top > int(options.top):
                    break
            percent = (float(self.freq[r]) / total) * 100.0
            print('{:02d}: {:30s} | hits = {:8d} ({:5.2f}%)'.format(
                top, self.country[r], self.freq[r], percent))
            top += 1
        print("""\
------------------------------------------------------------------""")

    def _asa_log(self, options):
        r_ip = r'((\d{1,3}\.){3}\d{1,3})'
        r_generic = r'[ a-zA-Z:\(\)_\-]+'
        r_proto = r'[A-Za-z]{2,4}'
        r_deny = r'^.+Deny\s{}\s{}{}/\d{{1,5}}{}{}.+$'.format(
            r_proto, r_generic, r_ip, r_generic, r_ip)
        r_built = r'''\
^.+Built{}\d+{}{}/\d{{1,5}}\s\({}/\d{{1,5}}\){}{}/\d{{1,5}}.+$'''.format(
            r_generic, r_generic, r_ip, r_ip, r_generic, r_ip)
        if options.ipv4:
            if options.asa_allow:
                rxp = re.compile(r_built)
            else:
                rxp = re.compile(r_deny)

        if options.src:
            gi = 1
        elif options.dst:
            gi = 3

        total = 0
        if options.asa == "-":
            f = sys.stdin.readlines()
        else:
            f = open(options.asa, 'r')

        for line in f:
            m = rxp.match(line)
            if not m:
                continue
            elif options.ipv4 and self._RFC1918(m.group(gi)):
                continue
            total += self._update_freq(m.group(gi))

        try:
            f.close()
        except:
            pass
        self._print_freq_summary('ASA', total)

    def _iptables_log(self, options):
        if options.ipv4:
            if options.src:
                rxp = re.compile(r'.+SRC=((\d{1,3}\.){3}\d{1,3})')
            elif options.dst:
                rxp = re.compile(r'.+DST=((\d{1,3}\.){3}\d{1,3})')
        elif options.ipv6:
            if options.src:
                rxp = re.compile(r'.+SRC=((\d{4}:){7}\d{4})')
            elif options.dst:
                rxp = re.compile(r'.+DST=((\d{4}:){7}\d{4})')

        total = 0
        if options.iptables == "-":
            f = sys.stdin.readlines()
        else:
            f = open(options.iptables, 'r')

        for line in f:
            m = rxp.match(line)
            if not m:
                continue
            elif options.ipv4 and self._RFC1918(m.group(1)):
                continue
            total += self._update_freq(m.group(1))
        try:
            f.close()
        except:
            pass
        self._print_freq_summary('IPTABLES', total)

    def _ipf_log(self, options):
        if options.ipv4:
            if options.src:
                rxp = re.compile(r'.+\s((\d{1,3}\.){3}\d{1,3})\,\d+\s->\s')
            elif options.dst:
                rxp = re.compile(r'.+\s->\s((\d{1,3}\.){3}\d{1,3})\,\d+')
        elif options.ipv6:
            if options.src:
                rxp = re.compile(r'.+\s((\d{4}:){7}\d{4})\,\d+\s->\s')
            elif options.dst:
                rxp = re.compile(r'.+\s->\s((\d{4}:){7}\d{4})\,\d+')

        total = 0
        if options.ipf == "-":
            f = sys.stdin.readlines()
        else:
            f = open(options.ipf, 'r')

        for line in f:
            m = rxp.match(line)
            if not m:
                continue
            elif options.ipv4 and self._RFC1918(m.group(1)):
                continue
            total += self._update_freq(m.group(1))
        try:
            f.close()
        except:
            pass
        self._print_freq_summary('IPF', total)

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
ORDER BY rir.cc, rir.type, rir.start_binary ASC
""".format(sql_type)
        cur.execute(sql)
        for r in cur.fetchall():
            cc = r[0]
            country_name = r[1]
            rirtype = r[5]
            if rirtype == 'ipv4':
                rnode = self.rib.add(r[2])
            elif rirtype == 'ipv6':
                rnode = self.rib.add('{}/{}'.format(r[3], r[4]))
            else:
                continue
            if cc not in self.country:
                self.country[cc] = country_name
            rnode.data['cc'] = cc
            rnode.data['country_name'] = country_name

    def _verify_file(self, options):
        if options.iptables:
            file = options.iptables
        elif options.asa:
            file = options.asa
        elif options.ipf:
            file = options.ipf
        else:
            print("No File specified")
            sys.exit(1)

        if not os.path.isfile(file) and str(file) != "-":
            print("File NOT Found: {}".format(file))
            sys.exit(1)

    def run(self, options):
        self._verify_file(options)
        self._get_dbrecords(options)
        if options.iptables:
            self._iptables_log(options)
        elif options.asa:
            self._asa_log(options)
        elif options.ipf:
            self._ipf_log(options)


if __name__ == '__main__':

    VERSION = '20150122_1105'
    desc = """
----------------------------------
 {} version {}
 Author: Joff Thyer (c) 2015
 Black Hills Information Security
----------------------------------
""".format(os.path.basename(sys.argv[0]), VERSION)
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=desc
    )
    parser.add_argument(
        '--iptables', help='specify iptables logfile'
    )
    parser.add_argument(
        '--asa', help='specify asa logfile'
    )
    parser.add_argument(
        '--ipf', help='specify BSD ipf logfile'
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
        '--asa_allow', action='store_true',
        default=False, help='search for built connection data instead of Deny'
    )
    parser.add_argument(
        '--top', default=10, help='output top [N|all] countries'
    )
    options = parser.parse_args()

    if not (options.ipv4 or options.iptables):
        parser.print_help()
        print('\nERROR: Please specify the --ipv4 flag and a log format')
        sys.exit(1)

    if not (options.src or options.dst):
        options.src = True

    print('{}'.format(desc))
    if not options.iptables and not options.asa and not options.ipf:
        print("Syntax error:")
        print("\tYou must specify at least one of:")
        print("\t\t--iptables [LOGFILE|-]")
        print("\t\t--asa [LOGFILE|-]\n")
        print("\t\t--ipf [LOGFILE|-]")
        print("\tTry running {} -h\n".format(sys.argv[0]))
        exit()
    logstats = RIRLogStats()
    logstats.run(options)
