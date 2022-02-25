#!/usr/bin/env python3

import argparse
import os
import sys
import csv
import re
import hashlib
import math
import urllib.request
import urllib.error
import urllib.parse
import sqlite3
import socket
from datetime import datetime, timedelta


class RIRDatabase:

    def __init__(self):
        self.ALLRIRS = [
            'arin', 'apnic', 'afrinic', 'lacnic', 'ripencc'
        ]
        dbhome = '{}/.rirdb'.format(os.path.expanduser('~'))
        if not os.path.exists(dbhome):
            os.mkdir(dbhome)
        self.dbname = '{}/rir.db'.format(dbhome)
        self.lastfetch = '{}/lastfetchdate'.format(dbhome)
        self.dbh = self.SQLconnect()

    def SQLconnect(self):
        dbh = sqlite3.connect(self.dbname)
        dbh.text_factory = str
        cur = dbh.cursor()
        sql = """\
CREATE TABLE IF NOT EXISTS rir
(
    registry TEXT, cc TEXT, type TEXT,
    start TEXT, start_binary INT, value TEXT, cidr TEXT,
    date TEXT, status TEXT, reg_id TEXT
)
"""
        cur.execute(sql)
        sql = """\
CREATE TABLE IF NOT EXISTS country_codes
(
    cc TEXT,
    name TEXT
)
"""
        cur.execute(sql)
        dbh.commit()
        return dbh

    def Insert_RIR_Records(self, rir, data):
        if not data:
            return [0, 0]
        cur = self.dbh.cursor()
        cur.execute('DELETE FROM rir WHERE registry = ?', [rir, ])
        self.dbh.commit()
        recs = 0
        errs = 0
        for line in data.split('\n'):
            if not line or \
                    re.match(r'^#', line) or \
                    re.match(r'^\d\.\d.+', line) or \
                    re.match(r'^.+\|summary', line):
                continue
            reg_id = ''
            try:
                registry, cc, type, start, \
                    value, date, status, reg_id = line.split('|')
            except:
                try:
                    registry, cc, type, start, \
                        value, date, status = line.split('|')
                except:
                    errs += 1
                    continue

            cidr = ''
            start_binary = 0
            if type == 'ipv4':
                start_binary = socket.inet_pton(
                    socket.AF_INET, start
                )
                cidr = '{}/{:d}'.format(
                    start, 32 - int(math.log(int(value), 2)))
            elif type == 'ipv6':
                start_binary = socket.inet_pton(
                    socket.AF_INET6, start
                )

            sql = """\
INSERT INTO rir (
    registry, cc, type, start, start_binary,
    value, cidr, date, status, reg_id
)
VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )
"""
            try:
                params = [
                    registry, cc, type, start, start_binary,
                    value, cidr, date, status, reg_id
                ]
                cur.execute(sql, params)
            except:
                errs += 1
                continue
            recs += 1
        self.dbh.commit()
        return [recs, errs]

    def fetchMD5(self, urlbase, datafile):
        url = '{}/{}.md5'.format(urlbase, datafile)
        req = urllib.request.Request(url)
        f = urllib.request.urlopen(req)
        line = f.read().decode()
        m = re.match(r'.*([a-f0-9]{32}).*', line)
        if m:
            return m.group(1)
        return None

    def GetRIRData(self, rir, datestr):
        if options.http:
            proto = "http"
        else:
            proto = "ftp"

        urlbase = '{}://ftp.{}.net/pub/stats/{}'.format(proto, rir, rir)
        if re.match(r'^ripencc', rir):
            urlbase = '{}://ftp.{}.net/pub/stats/{}'.format(proto, 'ripe', rir)
        datafile = 'delegated-{}-extended-{}'.format(rir, datestr)
        url = '{}/{}'.format(urlbase, datafile)
        req = urllib.request.Request(url)

        try:
            print('[*] Fetching [{}]'.format(datafile))
            f = urllib.request.urlopen(req)
            data = f.read()
            md5_1 = hashlib.md5(data).hexdigest()
            md5_2 = self.fetchMD5(urlbase, datafile)
            if md5_1 == md5_2:
                return [url, 'ok', data.decode()]
            else:
                return [url, 'error', 'md5 hash mismatch']
        except Exception as e:
            return [url, 'error', e]

    def RegionalRegistryData(self):
        for rir in self.ALLRIRS:
            done = False
            rdata = self.GetRIRData(rir, 'latest')
            if rdata[1] == 'ok':
                recs, errs = self.Insert_RIR_Records(rir, rdata[2])
                print('[*] Inserted {:d} records for [{}]'.format(recs, rir))
                if errs > 0:
                    raise Exception('[*] Errors on insert {:d}'.format(errs))
                done = True
            else:
                print('[-] ERROR: {}'.format(rdata))
            days = 0
            today = datetime.utcnow()
            while not done and days < 5:
                date = today - timedelta(days=-days)
                rdata = self.GetRIRData(rir, date.strftime('%Y%m%d'))
                if rdata[1] == 'ok':
                    recs, errs = self.Insert_RIR_Records(rir, rdata[2])
                    print('[*] Inserted {} records for [{}]'.format(recs, rir))
                    if errs > 0:
                        raise Exception(
                            '[*] Errors on insert {:d}'.format(errs)
                        )
                    done = True
                else:
                    print('[-] ERROR: {}'.format(rdata))
                days += 1

    def UpdateCountryCodes(self):
        cur = self.dbh.cursor()
        url = 'https://raw.githubusercontent.com/' + \
            'datasets/country-list/master/data.csv'
        req = urllib.request.Request(url)

        recs = 0
        f = urllib.request.urlopen(req)
        data = f.read().decode().split('\n')
        if not data:
            raise Exception('no data read from {}'.format(url))
        cur.execute('DELETE FROM country_codes')
        for line in csv.reader(data):
            if not line or (line[0] == 'Name' and line[1] == 'Code'):
                continue
            sql = "INSERT INTO country_codes (cc, name) VALUES (?, ?)"
            cc = line[1]
            name = line[0]
            cur.execute(sql, [cc, name])
            recs += 1

        cur.execute("""\
INSERT INTO country_codes VALUES ('EU', 'non-iso3166:Europe')""")
        cur.execute("""\
INSERT INTO country_codes VALUES ('AP', 'non-iso3166:Asia-Pacific')""")
        recs += 2
        self.dbh.commit()
        print('[*] %d country codes updated.' % (recs))

    def has_run_today(self):
        today = datetime.utcnow().strftime('%Y%m%d')
        with open(self.lastfetch, 'r') as f:
            last = f.read()[:-1]
            f.close()
        if today == last:
            return True
        return False

    def UpdateLastDate(self):
        today = datetime.utcnow().strftime('%Y%m%d')
        f = open(self.lastfetch, 'w')
        f.write('{}\n'.format(today))
        f.close()

    def run(self):
        if self.has_run_today() and not options.force:
            print('[*] Exiting: Data has already been fetched today')
            return
        self.UpdateCountryCodes()
        self.RegionalRegistryData()
        self.UpdateLastDate()


if __name__ == '__main__':

    VERSION = '20220225_0101'
    desc = '''
-------------------------------------------------
   {} Version {}
   Author: Joff Thyer (c) 2015-2022
   Black Hills Information Security
-------------------------------------------------
'''.format(os.path.basename(sys.argv[0]), VERSION)
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=desc
    )
    parser.add_argument(
        '--http', action='store_true',
        default=False, help='Retrieve RIR data over HTTP'
    )
    parser.add_argument(
        '--force', action='store_true',
        default=False, help='Force DB update'
    )
    options = parser.parse_args()

    print('{}'.format(desc))
    rirdb = RIRDatabase()
    rirdb.run()
