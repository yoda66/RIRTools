#!/usr/bin/env python

import argparse
import os
import sys
import csv
import re
import hashlib
import math
import urllib2
import sqlite3
import socket
from datetime import datetime, timedelta


class RIRDatabase:

    def __init__(self):
        self.ALLRIRS = [
            'arin', 'apnic', 'afrinic', 'lacnic', 'ripencc'
        ]
        dbhome = '%s/.rirdb' % (os.path.expanduser('~'))
        if not os.path.exists(dbhome):
            os.mkdir(dbhome)
        self.dbname = '%s/rir.db' % (dbhome)
        self.lastfetch = '%s/lastfetchdate' % (dbhome)
        self.dbh = self._sqlite3_connect()

    def _sqlite3_connect(self):
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

    def _insert_rir_recs(self, rir, data):
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
                cidr = '%s/%d' % \
                    (
                        start,
                        32 - int(math.log(int(value), 2))
                    )
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

    def _get_md5file(self, urlbase, datafile):
        url = '%s/%s.md5' % (urlbase, datafile)
        req = urllib2.Request(url)
        try:
            f = urllib2.urlopen(req)
            line = f.read()
            m = re.match(r'^.*([a-f0-9]{32}).*$', line)
            if m:
                return m.group(1)
        except:
            return None
        return None

    def _get_rirdata(self, rir, datestr):
        if options.http:
            proto="http"
        else:
            proto="ftp"

        urlbase = '%s://ftp.%s.net/pub/stats/%s' % \
            (proto, rir, rir)
        if re.match(r'^ripencc', rir):
            urlbase = '%s://ftp.%s.net/pub/stats/%s' % \
                (proto, 'ripe', rir)
        datafile = 'delegated-%s-extended-%s' % (rir, datestr)
        url = '%s/%s' % (urlbase, datafile)
        req = urllib2.Request(url)

        try:
            print '[*] Fetching [%s]' % (datafile)
            f = urllib2.urlopen(req)
            data = f.read()
            md5_1 = hashlib.md5(data).hexdigest()
            md5_2 = self._get_md5file(urlbase, datafile)
            if md5_1 == md5_2:
                return [url, 'ok', data]
            else:
                return [url, 'error', 'md5 hash mismatch']
        except Exception as e:
            return [url, 'error', e]

    def regional_registry_data(self):
        for rir in self.ALLRIRS:
            done = False
            rdata = self._get_rirdata(rir, 'latest')
            if rdata[1] == 'ok':
                recs, errs = self._insert_rir_recs(rir, rdata[2])
                print '[*] Inserted %d records for [%s]' % \
                    (recs, rir)
                if errs > 0:
                    raise Exception('[*] Errors on insert %d' % (errs))
                done = True
            else:
                print '[-] ERROR: %s' % (rdata)
            days = 0
            today = datetime.utcnow()
            while not done and days < 5:
                date = today - timedelta(days=-days)
                rdata = self._get_rirdata(rir, date.strftime('%Y%m%d'))
                if rdata[1] == 'ok':
                    recs, errs = self._insert_rir_recs(rir, rdata[2])
                    print '[*] Inserted %d records for [%s]' % \
                        (recs, rir)
                    if errs > 0:
                        raise Exception('[*] Errors on insert %d' % (errs))
                    done = True
                else:
                    print '[-] ERROR: %s' % (rdata)
                days += 1

    def update_country_codes(self):
        cur = self.dbh.cursor()
        url = 'https://raw.githubusercontent.com/' + \
            'datasets/country-list/master/data.csv'
        req = urllib2.Request(url)
        try:
            recs = 0
            f = urllib2.urlopen(req)
            data = f.read().split('\n')
            if not data:
                raise Exception('no data read from %s' % (url))
            cur.execute('DELETE FROM country_codes')
            for line in csv.reader(data):
                if not line or (line[0] == 'Name' and line[1] == 'Code'):
                    continue
                sql = "INSERT INTO country_codes (cc, name) VALUES (?, ?)"
                cc = unicode(line[1])
                name = unicode(line[0], errors='ignore')
                cur.execute(sql, [cc, name])
                recs += 1
        except Exception as e:
            print '[*] Exception: %s' % (e)
            return
        cur.execute("INSERT INTO country_codes VALUES ('EU', 'non-iso3166:Europe')")
        cur.execute("INSERT INTO country_codes VALUES ('AP', 'non-iso3166:Asia-Pacific')")
        recs += 2
        self.dbh.commit()
        print '[*] %d country codes updated.' % (recs)

    def has_run_today(self):
        today = datetime.utcnow().strftime('%Y%m%d')
        try:
            f = open(self.lastfetch, 'r')
            last = f.read()[:-1]
            f.close()
            if today == last:
                return True
        except:
            pass
        return False

    def update_lastdate(self):
        today = datetime.utcnow().strftime('%Y%m%d')
        f = open(self.lastfetch, 'w')
        f.write('%s\n' % (today))
        f.close()

    def run(self):
        if self.has_run_today() and not options.force:
            print '[*] Exiting: Data has already been fetched today'
            return
        self.update_country_codes()
        self.regional_registry_data()
        self.update_lastdate()


if __name__ == '__main__':

    VERSION = '20150122_1035'
    desc = """
[*] ---------------------------------------------
[*] %s version %s
[*] Author: Joff Thyer (c) 2015
[*] Black Hills Information Security
[*] ---------------------------------------------
""" % (os.path.basename(sys.argv[0]), VERSION)
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

    print '%s' % (desc)
    rirdb = RIRDatabase()
    rirdb.run()
