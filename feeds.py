#!/bin/python

#
# The MIT License (MIT)
#
# Copyright (c) 2015 JP Senior jp.senior@gmail.com
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

# This file is used to configure a list of feeds a user is interested in acquiiring
feeds = [

    dict(
        type='alienvault',
        url='https://reputation.alienvault.com/reputation.data',
        source='alienvault.com',
        description='alienvault'),
    dict(
        type='malcode',
        url='http://malc0de.com/bl/IP_Blacklist.txt',
        description='malc0de.com IP Blacklist'),
    dict(
        type='emerging-compromised',
        url='http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        description='emergingthreats.net Compromised IPs'),
    dict(
        type='emerging-block',
        url='http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
        description='emerginghtreats.net Blocked IPs'),
    dict(
        type='palveo',
        url='https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist',
        description='abuse.ch Palveo Tracker'),
    dict(
        type='binarydefense',
        url='http://www.binarydefense.com/banlist.txt',
        description='Binary Defense Systems Banlist'),
    dict(
        type='ssl-blacklist',
        url='https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',
        description='abuse.ch SSL Blacklist'),
    dict(
        type='zeus',
        url='https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist',
        description='abuse.ch Zeus tracker'),
    dict(
        type='nothink-ssh',
        url='http://www.nothink.org/blacklist/blacklist_ssh_all.txt',
        description='nothink SSH Blacklist'),
    dict(
        type='malwaredomain',
        url='http://www.malwaredomainlist.com/hostslist/ip.txt',
        description='malwaredomainlist IP'),
    dict(
        type='ciarmy-badguys',
        url='http://www.ciarmy.com/list/ci-badguys.txt',
        description='ciarmy IP'),
    dict(
        type='autoshun',
        url='http://autoshun.org/files/shunlist.csv',
        description='Autoshun list'),
]
