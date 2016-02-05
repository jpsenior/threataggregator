#!/bin/python
#
#
# The MIT License (MIT)
#
# Copyright (c) 2016 JP Senior jp.senior@gmail.com
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# "This product includes GeoLite data created by MaxMind, available from
# http://maxmind.com/"
#
# Additional thanks to Seth Golub for heatmap - a fun little diversion with the resultant data.
# Copyright 2010 Seth Golub
# http://www.sethoscope.net/heatmap/
#
#
# RepDB
# This program scrapes reputation database information from a number of internet sources
# and creates CEF entries to update, add, or remove new, expired, and similar information
# from free threat sources on the Internet.
# These CEF entries are then forwarded via a simple syslog to a centralized server for later
# SIEM analysis (eg Splunk, Arcsight, Alienvault)
# Correlating these reputation entries agaisnt firewall, web proxy, IPS/IDS, etc logs enables
# an administrator to drill down into problem areas in their network.
#
# Some mechanisms are in place to assist with geolocation of asset information 
# unique IP addresses.
#

import sys
import difflib
import re
import os
import csv
import socket
import time
import datetime
import geoip2.database
import geoip2.errors
import gzip
import maxminddb.errors
import netaddr
import json
import requests

from feeds import feeds
import config

FACILITY = dict(kern=0, user=1, mail=2, daemon=3, auth=4, syslog=5, lpr=6, news=7, uucp=8, cron=9, authpriv=10, ftp=11,
                local0=16, local1=17, local2=18, local3=19, local4=20, local5=21, local6=22, local7=23)

LEVEL = dict(emerg=0, alert=1, crit=2, err=3, warning=4, notice=5, info=6, debug=7)

# Regular Expression for dotted-quad IP addresses with or without CIDR suffixes
re_ipcidr = (r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)'
             '{3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
             '((/([0-9]|[1-2][0-9]|3[0-2]){0,2})?)')

if not re.match(re_ipcidr, config.host):
    raise Exception(ValueError, "Syslog host %s is not valid" % config.host)


def download_file(url, filename):
    """
    :param url: URL of file to download
    :param filename: Filename to write the result object to
    :return:
    """
    r = requests.get(url, stream=True, proxies=config.proxies, verify=config.verifySSL)

    with open(filename, 'wb') as fd:
        for chunk in r.iter_content(1024):
            fd.write(chunk)


class RepDB(list):
    """ Reputation database class to store entries

    """

    def __init__(self):
        super(RepDB, self).__init__()
        self.entries = []

    def add(self, ip, source, description, priority=1, reputation=1, latitude=0.000000, longitude=0.000000, city='',
            country=''):
        """

        :param string ip: IP is a dotted quad x.x.x.x or CIDR x.x.x.x/yy
        :param string source: Source for ThreatDB entry URL
        :param string description: Description of this individual entry
        :param int priority: Priority of threat
        :param int reputation: Reputation of threat
        :param float latitude: Latitude of threat entry
        :param float longitude: Longitude of threat entry
        :param string city: City of located threat
        :param string country: Country of located threat
        :return:
        """

        if not re.match(re_ipcidr, ip):
            # How did we get here?
            raise Exception(ValueError, "IP %s is not valid" % ip)

        try:
            reader = get_geo_db()

            # Use netaddr to convert CIDR to a network ID, allowing us to extract cities properly.
            response = reader.city(netaddr.IPNetwork(ip).network)
            if not city:
                city = response.city.name
            if not country:
                country = response.country.name
            if not latitude:
                if response.location.latitude:
                    latitude = response.location.latitude
                else:
                    latitude = 0
            if not longitude:
                if response.location.longitude:
                    longitude = response.location.longitude
                else:
                    longitude = 0
            # Close the GeoDB reader
            reader.close()

        # Not all IP addresses will be in the Maxmind database
        except geoip2.errors.AddressNotFoundError:
            pass

        except maxminddb.errors.InvalidDatabaseError as e:
            raise "Invalid GeoIP database %s" % e

        # Signed degrees format for latitude and longitude
        # Represented DDD.ddd with maximum 8 decimal places.
        # Longitudes range from -90 to 90
        # Latitudes range from -180 to 180
        if latitude < -90.0 or latitude > 90.0:
            latitude = 0
        if longitude < -180.0 or longitude > 180.0:
            longitude = 0
        # Translate CIDR to a list of IP addresses for Arcsight
        for i in netaddr.IPNetwork(ip):
            self.entries.append(
                {'ip': i, 'source': source, 'description': description, 'priority': priority,
                 'reputation': reputation, 'latitude': latitude, 'longitude': longitude, 'city': city,
                 'country': country})

    def __count__(self):
        """ Returns count of RepDB entries.

        :return:
        """
        return len(self)

    def __iter__(self):
        """ Custom iterator to use entries instead of the object itself
        :return:
        """
        for e in self.entries:
            # print("Entry: {}".format(e))
            yield e

    def __getitem__(self, item):
        """
        :param int item: Integer index of entry item
        :return: Returns selected item slice
        """
        return self.entries[item]

    def __len__(self):
        return len(self.entries)

    def search(self, ip, top=False):
        """ Allows you to search the reputation database on a destination IP address
            If found, returns a list of RepDB entries containing information about IP.
            Specifying top=true only returns the first entry

        :param ip: IP to search RepDB for
        :param BOOL top: Returns the 'first' entry if true or 'all' matching entries if false
        :return: Returns a list of results, or False if no results
        """
        results = []
        for entry in self:
            if netaddr.IPNetwork(ip).network in netaddr.IPNetwork(entry['ip']):
                if top:
                    results.append(entry)
                    return results
                results.append(entry)
        # list of results
        return results


class BuildCompare:
    """ Uses difflib.SequenceMatcher to compare list 'a' and list 'b' and return results accordingly
    c = buildcompare(list(a),list(b))
    c.add() returns a list of items 'new' to add
    c.delete() returns a list of items 'old' to remove
    end state is to send CEF-based syslog packets to Arcsight for adding and removing threat events from a feed
    """

    def __init__(self, old, new):
        """
        :param list old: List of 'old' lines to compare to new
        :param list new: List of 'new' lines to compare to old
        :return:
        """

        # Compares best when items are sorted
        old.sort()
        new.sort()
        self.add = []
        self.delete = []
        self.equal = []
        s = difflib.SequenceMatcher(None, old, new)
        for tag, i1, i2, j1, j2 in s.get_opcodes():

            # This helps to understand what we're adding and removing. From difflib documentation
            if config.debug:
                print("%7s a[%d:%d] (%s) b[%d:%d] (%s)" % (tag, i1, i2, old[i1:i2], j1, j2, new[j1:j2]))

            # replace takes out items from list A[i1:i2] and adds from list B[j1:j2]
            if tag == 'replace':
                for i in old[i1:i2]:
                    self.delete.append(i)
                for i in new[j1:j2]:
                    self.add.append(i)
            # delete records are not seen in list b. Remove items from list a[i1:i2]
            elif tag == 'delete':
                for i in old[i1:i2]:
                    self.delete.append(i)
            # insert records are not seen in list a. Add items from list b.
            elif tag == 'insert':
                for i in new[j1:j2]:
                    self.add.append(i)
            elif tag == 'equal':
                for i in old[i1:i2]:
                    self.equal.append(i)

    def add(self):
        """ Returns a list of items to add

        :return: Returns a list of items to ADD
        """
        return self.add

    def delete(self):
        """ Returns a list of items to delete

        :return: Returns a list of items to delete
        """
        return self.delete

    def equal(self):
        """ Returns a list of unchanged items

        :return:Returns a list of unchanged items
        """
        return self.equal


def syslog(message):
    """ Send a UDP syslog packet

    :param string message: Sends a raw message to syslog
    :return:
    """
    level = LEVEL['info']
    facility = FACILITY['local0']

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # We have to encode as UTF8 for non-ascii characters.

    data = u'<%d>%s' % (level + facility * 8, message)
    s.sendto(data.encode('utf-8'),(config.host, config.port))
    s.close()


def get_geo_db():
    """ Finds and caches a maxmind database for GeoIP2
    from http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz

    :return: geoip2.database.Reader object
    """

    # Pull everything off the internet if it isn't cached
    geofilename = 'cache/GeoLite2-City.mmdb'
    url = 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz'
    gzipfile = 'cache/GeoLite2-City.mmdb.gz'

    if os.path.isfile(geofilename):
        try:
            reader = geoip2.database.Reader(geofilename)
        except ValueError as e:
            raise Exception("Error accessing GeoLite database: %s" % e)
        except maxminddb.errors.InvalidDatabaseError as e:
            raise Exception("Invalid DB error %s - %s " % (geofilename, e))
        return reader
    else:

        try:
            print("Maxmind database not cached. Attempting to pull from {0}".format(url))
            download_file(url, gzipfile)
        except requests.ConnectionError:
            e = sys.exc_info()[0]
            print('Connection interrupted while downloading Maxmind Database: {0} - {1}'.format(url, e))
        except IOError:
            e = sys.exc_info()[0]
            print('Error downloading Maxmind Database: %s - %s'.format(url, e))

        # Open Gzip
        f = gzip.open(gzipfile, 'rb')
        maxmind = f.read()
        f.close()

        # Re-Write uncompressed format
        f = open(geofilename, 'wb')
        f.write(maxmind)
        f.close()

        # Wrap up
        reader = geoip2.database.Reader(geofilename)
        return reader


def emergingthreat(url, data):
    """ Builds an emergingthreat.net specific Block IP list with special parsing mechanisms

    Emergingthreat.net Block-IP list is formatted in a special way so we have to parse it
    differently.  Each category (description) is separated by two whitespaces and a hash
    and entries following are individual reputation entries.
    EG:

    #header
    #header

    #Spam

    1.2.3.4
    2.3.4.5

    #Malware

    9.9.9.9
    10.10.10.10

    :param string url: URL for Emergingthreat.net to include in db entry
    :param list data: list() of lines to parse
    :return: RepDB: A RepDB() instance containing threat information
    """
    repdb = RepDB()
    re_section = r'^#(.*)'
    iptype = ''
    for line in data:
        typematch = re.match(re_section, line)
        ipmatch = re.match(re_ipcidr, line)
        if typematch:
            # Get rid of extra whitespace. Match group '1'.
            iptype = ' '.join(typematch.group(1).split())
        elif ipmatch:
            # Spamhaus are too big and too annoying.  They break RepDB later when we parse out CIDR
            if iptype != 'Spamhaus DROP Nets':
                ip = ipmatch.group(0)
                repdb.add(ip, url, iptype)
    return repdb


def ipfeed(url, description, data):
    """ Builds reputation DB based on one IP per line
    Only imports valid IPs

    Format is one IP per line with no further details. EG:

    1.2.3.4
    3.4.5.2
    9.9.9.9

    :param string url: URL for generic IP feed to include in DB entry
    :param string description: Description of DB entry
    :param list data: List of lines to parse
    :return: RepDB: A RepDB() instance containing threat information
    """
    repdb = RepDB()
    for line in data:
        ipmatch = re.match(re_ipcidr, line)
        if ipmatch:
            ip = ipmatch.group(0)
            repdb.add(ip, url, description)
    return repdb


def sslblacklist(url, data):
    """ Parse SSLBlacklist CSV entries
    Format is:
    ip,port,description


    :param string url: URL for generic IP feed to include in DB entry
    :param list data: List of lines to parse
    :return:RepDB: A RepDB() instance containing threat information
    """
    repdb = RepDB()
    reader = csv.reader(data, delimiter=',')

    for line in reader:
        ipmatch = re.match(re_ipcidr, line[0])
        if ipmatch:
            ip = ipmatch.group(0)
            repdb.add(ip, url, line[2])
    return repdb


def autoshun(url, data):
    """ Parse Autoshun CSV entries
    Format is:
    ip,port,description


    :param string url: URL for generic IP feed to include in DB entry
    :param list data: List of lines to parse
    :return: RepDB: A RepDB() instance containing threat information
    """
    repdb = RepDB()
    reader = csv.reader(data, delimiter=',')

    for line in reader:
        ipmatch = re.match(re_ipcidr, line[0])
        if ipmatch:
            ip = ipmatch.group(0)
            repdb.add(ip, url, line[2])
    return repdb


def alienvault(url, data):
    """ Parse alienvault reputation db entries. These are pretty complicated so a simpler parser is used.

    Format is:
    #<IP>#<PRIORITY>#<CONFIDENCE>#<Description>#<COUNTRY>#<CITY>#<LATITUDE>,<LONGITUDE>#??

    :param string url: URL for generic IP feed to include in DB entry
    :param list data: List of lines to parse
    :return: RepDB: A RepDB() instance containing threat information
    """
    repdb = RepDB()

    def check_reputation_format(ln):
        r = re.compile("^[+-]?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#\d\d?#\d\d?#.*#.*#.*#.*#.*$")
        if ln != "":
            if not r.match(ln):
                return False
        return True

    for d in data:
        if check_reputation_format(d) and d != "":
            if d[0] == "-":
                continue
            if d[0] == "+":
                d = d[1:]
            fs = d.split("#")
            if len(fs) == 8:
                # Check parameters
                # Some variables are unsed; Alienvault includes its own repDB entry for maxmind lookups
                # but we prefer to do it ourselves
                ip = fs[0]
                rel = int(fs[1])
                prio = int(fs[2])
                desc = fs[3]

                repdb.add(ip, url, desc, priority=prio, reputation=rel)
    return repdb


def build_db(dbtype, url, description, db_add, db_del, db_equal):
    """ Builds reputation database entry based on type
    Assumes default type 'ipfeed'

    :param string dbtype: User-specified 'type' for feed name. Constructs filename
    :param string url: URLLib http GET url to obtain threat entries
    :param string description: User description of threat feed
    :param db_add: Entry database for 'new' items
    :param db_del Entry database for 'new' items
    :param db_equal: Entry database for 'new' items
    :return:
    """

    old_filename = 'cache/%s.txt' % dbtype
    new_filename = 'cache/%s.txt.compare_add' % dbtype

    if not os.path.exists('cache'):
        os.makedirs('cache')

    try:
        download_file(url, new_filename)
    except requests.ConnectionError as e:
        print('Connection interrupted while downloading: {0} - {1}'.format(url, e))
        # If there's a problem just keep going.
        return

    except IOError:
        e = sys.exc_info()[0]
        print('Error downloading: {0} - {1}'.format(url, e))
        raise IOError('Something happened {0}'.format(e))

    if os.path.isfile(new_filename):
        with open(new_filename, 'r') as fn:
            compare_add = fn.read().splitlines()
    else:
        compare_add = []

    if os.path.isfile(old_filename):
        with open(old_filename, 'r') as fn:
            compare_delete = fn.read().splitlines()
    else:
        compare_delete = []
    print('Comparing {0} downloaded to {1} cached lines'.format(len(compare_add), len(compare_delete)))

    compare = BuildCompare(compare_delete, compare_add)
    compare_delete = compare.delete
    compare_add = compare.add
    compare_equal = compare.equal
    print("{0} new, {1} deleted, {2} unchanged lines".format(len(compare_add), len(compare_delete),
                                                             len(compare_equal)))

    if dbtype == 'alienvault':
        db_del.append(alienvault(url, compare_delete))
        db_add.append(alienvault(url, compare_add))
        db_equal.append(alienvault(url, compare_equal))
    elif dbtype == 'emerging-block':
        db_del.append(emergingthreat(url, compare_delete))
        db_add.append(emergingthreat(url, compare_add))
        db_equal.append(emergingthreat(url, compare_equal))

    elif dbtype == 'ssl-blacklist':
        db_del.append(sslblacklist(url, compare_delete))
        db_add.append(sslblacklist(url, compare_add))
        db_equal.append(sslblacklist(url, compare_equal))
    elif dbtype == 'ssl-blacklist':
        db_del.append(autoshun(url, compare_delete))
        db_add.append(autoshun(url, compare_add))
        db_equal.append(autoshun(url, compare_equal))
    else:
        db_del.append(ipfeed(url, description, compare_delete))
        db_add.append(ipfeed(url, description, compare_add))
        db_equal.append(ipfeed(url, description, compare_equal))

    if not os.path.exists('cache'):
        os.makedirs('cache')

    if os.path.isfile(old_filename):
        try:
            os.remove(old_filename)
        except (IOError, OSError) as e:
            raise OSError('Could not remove file: {0}- {1}'.format(old_filename, e))
    try:
        os.rename(new_filename, old_filename)
    except (IOError, OSError) as e:
        raise OSError('Could not rename {0} to {1} - {2}'.format(new_filename, old_filename, e))


def printjson(action, entry):
    """ Prints a JSON-formatted object for an action and entry
   
    :param string action:  add remove or delete
    :param entry: One RepDB entry to print JSON output for
    :return: null
    """
    outjson = json.dumps({
        action: {
            'ip': str(entry['ip']),
            'source': entry['source'],
            'description': entry['description'],
            'priority': entry['priority'],
            'reputation': entry['reputation'],
            'city': entry['city'],
            'country': entry['country'],
            'latitude': entry['latitude'],
            'longitude': entry['longitude'],
        }
    })
    print(outjson)


def buildcef(action, entry):
    """ Builds a CEF-formatted string based on reputation entry from RepDB

    :param string action:  add remove or delete
    :param entry: One RepDB entry to parse
    :return: Returns a CEF-formatted string with timestamp
    """
    ip = entry['ip']
    source = entry['source']
    description = entry['description']
    priority = entry['priority']
    reputation = entry['reputation']
    city = entry['city']
    country = entry['country']
    latitude = entry['latitude']
    longitude = entry['longitude']

    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%b %d %Y %H:%M:%S')
    return ('%s %s CEF:0|%s|%s|1.0|100|Threat Entry %s|1|act=%s reason=%s src=%s '
            'cs1Label=Source cs1=%s cs2Label=City cs2=%s cs3Label=Country cs3=%s '
            'cfp1Label=Latitude cfp1=%.8f cfp2Label=Longitude cfp2=%.8f cfp3Label=Priority '
            'cfp3=%d cfp4Label=Reputation cfp4=%d') % (
               timestamp, config.deviceHost, config.deviceVendor, config.deviceProduct, action, action,
               description, ip, source, city, country, latitude, longitude, priority, reputation
           )


def start(feedlist, db_add, db_del, db_equal):
    """ Begins scraping URLs and building reputation DB entities.
    :param feedlist: list of dictionary elements containing type, url, description
    :param db_add: RepDB of new entries
    :param db_del: RepDB of removed entries
    :param db_equal: RepDB of unchanged entries (updated)
    :return:
    """
    for i in feedlist:
        print("Processing {0} from {1}".format(i['description'], i['url']))
        build_db(i['type'], i['url'], i['description'], db_add, db_del, db_equal)


def process(db_add, db_del, db_equal):
    """ Processes RepDB entries in order for syslog, stdout, csv file, etc

    :param repDB db_add: RepDB entry to show added items
    :param repDB db_del: RepDB entry to show deleted items
    :param repDB db_equal: RepDB entry to show unchanged values
    """

    # fun toy for heatmaps later
    f = open('cache/coords.txt', 'w')
    count_add = 0
    count_del = 0
    count_equal = 0

    for line in db_add:

        for i in line:
            count_add += 1
            msg = buildcef('add', i)
            syslog(msg)
            if config.debug:
                printjson('add', i)
            f.write("%s %s\n" % (i['latitude'], i['longitude']))

    for line in db_del:
        for i in line:
            count_del += 1
            msg = buildcef('delete', i)
            if config.debug:
                printjson('delete', i)
            syslog(msg)

    for line in db_equal:
        for i in line:
            count_equal += 1
            msg = buildcef('update', i)
            syslog(msg)
            if config.debug:
                printjson('update', i)
            f.write("%s %s\n" % (i['latitude'], i['longitude']))

    f.close()
    print("Sent {0} New, {1} deleted, and {2} unchanged entries to {3}:{4}".format(
        count_add, count_del, count_equal, config.host, config.port))

# Only run code if invoked directly: This allows a user to import modules without having to run through everything
if __name__ == "__main__":
    _db_add = []
    _db_del = []
    _db_equal = []

    start(feeds, _db_add, _db_del, _db_equal)
    process(_db_add, _db_del, _db_equal)
