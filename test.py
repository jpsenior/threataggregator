__author__ = 'JP Senior'
import unittest
from netaddr import IPAddress
from threataggregator import *


class RepDBTest(unittest.TestCase):
    """ Tests the RepDB class object and constructors
    """

    # Invoked before each test method
    def setUp(self):
        self.db = RepDB()
        self.db.add('127.0.0.1', 'http://localhost2', 'CIDR test')
        self.db.add('127.0.0.2', 'http://localhost3', 'Localhost test2')
        self.db.add('127.0.0.3', 'http://localhost3-A', 'Localhost test3-A')
        self.db.add('127.0.0.3', 'http://localhost3-B', 'Localhost test3-B')
        self.db.add('127.0.0.4', 'http://localhost4', 'Localhost test4')

    def test_len(self):
        # We expect exactly 5 entries in the database
        self.assertEqual(len(self.db), 5)

    def test_search(self):
        # There should be two results for 127.0.0.3
        results = self.db.search('127.0.0.3')
        self.assertEqual(len(results), 2)

    def test_search_top(self):
        # There should be only one result for 127.0.0.3 if Top=True
        results = self.db.search("127.0.0.3", top=True)
        self.assertEqual(len(results), 1)

    def test_search_empty(self):
        # An invalid IP address should return an empty list
        results = self.db.search("4.4.4.4")
        self.assertEqual(len(results), 0, "An invalid IP should return a zero-length list")
        self.assertListEqual(results, [], "Searching for an invalid IP should return an empty list")

    def test_cidr(self):
        db = RepDB()
        db.add('127.0.0.0/24', 'http://localhost2', 'CIDR test')
        # 256 IP addresses in a subnet

        #There should be 256 IPs in a subnet
        self.assertEqual(len(db), 256)
        # First IP should be .0
        #
        self.assertEqual(db.entries[0]['ip'], IPAddress('127.0.0.0'), "First IP in range is not valid")
        # Last IP should be .255
        self.assertEqual(db.entries[-1]['ip'], IPAddress('127.0.0.255'), "Last IP in range is not valid")

    def test_geo_locate(self):
        pass


class FakeUrlLib(object):
    pass


def urlopen(xurl):
    return xurl


class BuildCompareTest(unittest.TestCase):
    """ Tests for the BuildCompare class object
    """

    def setUp(self):
        old = ['127.0.0.1', '127.0.0.2', '127.0.0.3', '127.0.0.4', '127.0.0.5']
        new = ['127.0.0.1', '127.0.0.3', '127.0.0.4', '127.0.0.5', '127.0.0.6', '127.0.0.7']
        self.compare = BuildCompare(old, new)

    def test_add(self):
        # Only .6 and .7 are added.
        self.assertListEqual(self.compare.add, ['127.0.0.6', '127.0.0.7'])

    def test_delete(self):
        # only .2 is added
        self.assertListEqual(self.compare.delete, ['127.0.0.2'])

    def test_equal(self):
        # .1, .3, .4, .5 are equal.
        self.assertListEqual(self.compare.equal, ['127.0.0.1', '127.0.0.3', '127.0.0.4', '127.0.0.5'])


class EmergingThreatTest(unittest.TestCase):
    def setUp(self):
        self.data = '''
#Type1

107.150.36.226
109.123.109.132
123.157.215.216
173.230.133.99


#Type2

1.116.0.0/24
5.34.242.0/24
5.72.0.0/24
14.4.0.0/24

'''.splitlines()
        self.db = RepDB()

    def test_emerging_threat(self):
        self.db = emergingthreat('http://localhost.com', self.data)
        self.assertDictEqual(self.db.entries[0], {'priority': 1, 'source': 'http://localhost.com', 'reputation': 1,
                                                  'description': 'Type1', 'city': u'Kansas City', 'latitude': 39.1472,
                                                  'ip': IPAddress('107.150.36.2'), 'country': u'United States',
                                                  'longitude': -94.5735}, "RepDB results did not come back as expected")

if __name__ == "__main__":
    unittest.main()
