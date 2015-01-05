#!/usr/bin/env python

import os
import csv
import re
import hashlib
import math
import urllib2
import sqlite3
from datetime import datetime, timedelta


class RIRDatabase:

    def __init__(self):
        dbhome = '%s/.rirdb' % (os.path.expanduser('~'))
        if not os.path.exists(dbhome):
            os.mkdir(dbhome)
        self.dbname = '%s/rir.db' % (dbhome)
        self.dbh = self._sqlite3_connect()

    def _sqlite3_connect(self):
        dbh = sqlite3.connect(self.dbname)
        cur = dbh.cursor()
        sql = """\
CREATE TABLE IF NOT EXISTS rir
(
    registry TEXT, cc TEXT, type TEXT,
    start TEXT, value TEXT, cidr TEXT,
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
            if type == 'ipv4':
                cidr = '%s/%d' % \
                    (
                        start,
                        32 - int(math.log(int(value), 2))
                    )

            sql = """\
INSERT INTO rir
(registry, cc, type, start, value, cidr, date, status, reg_id)
VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ? )
"""
            try:
                params = [
                    registry, cc, type, start, value,
                    cidr, date, status, reg_id
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
        urlbase = 'ftp://ftp.%s.net/pub/stats/%s' % \
            (rir, rir)
        if re.match(r'^ripencc', rir):
            urlbase = 'ftp://ftp.%s.net/pub/stats/%s' % \
                ('ripe', rir)
        datafile = 'delegated-%s-extended-%s' % (rir, datestr)
        url = '%s/%s' % (urlbase, datafile)
        req = urllib2.Request(url)

        try:
            print '[*] Fetching [%s]' % (url)
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
        ALLRIRS = ['arin', 'apnic', 'afrinic', 'lacnic', 'ripencc']

        for rir in ALLRIRS:
            done = False
            rdata = self._get_rirdata(rir, 'latest')
            if rdata[1] == 'ok':
                ret = self._insert_rir_recs(rir, rdata[2])
                print '[*] Records inserted for %s: %s' % (rir, ret)
                done = True
            else:
                print '[-] ERROR: %s' % (rdata)
            days = 0
            today = datetime.utcnow()
            while not done and days < 5:
                date = today - timedelta(days=-days)
                rdata = self._get_rirdata(rir, date.strftime('%Y%m%d'))
                if rdata[1] == 'ok':
                    ret = self._insert_rir_recs(rir, rdata[2])
                    print '[*] Records inserted for %s: %s' % (rir, ret)
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
        self.dbh.commit()
        print '[*] %d country codes updated.' % (recs)

    def run(self):
        self.update_country_codes()
        self.regional_registry_data()


if __name__ == '__main__':
    rirdb = RIRDatabase()
    rirdb.run()
