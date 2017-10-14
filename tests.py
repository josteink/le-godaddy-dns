# -*- coding: utf-8 -*-

import os
os.environ["GD_KEY"] = "key"
os.environ["GD_SECRET"] = "secret"

import unittest
import godaddy


class Tests(unittest.TestCase):
    def test_parse_tld(self):
        testcase = "kjonigsen.net"
        result = godaddy._get_zone(testcase)
        self.assertEqual("kjonigsen.net", result)

        testcase = "subdomain.kjonigsen.net"
        result = godaddy._get_zone(testcase)
        self.assertEqual("kjonigsen.net", result)
