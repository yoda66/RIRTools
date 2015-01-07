#!/usr/bin/env python

import os
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

    def _get_ipv4_cidr(self, cc=None):
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
        if cc:
            sql += 'AND rir.cc == %s' % (cc)

        sql += 'ORDER BY country_codes.cc, rir.start_binary ASC'
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

    def run(self):
        self._get_ipv4_cidr()
        self._ipv4_iptables()

if __name__ == '__main__':
    riracl = RIRACL()
    riracl.run()
