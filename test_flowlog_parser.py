#!/usr/bin/env python3

import unittest
from code.flowlog_parser import *

class TestFlowLogParser(unittest.TestCase):
    def test_negative_case(self):
        flp = DefaultFlowLogsParser(2, "dummy", "dummy", "dummy")
        lines = ["abc", "def", "ghi"]
        flp._analyze_flow_logs(lines)
        self.assertTrue(flp.errors > 0)
        self.assertEqual(len(flp.tag_count), 0)
        self.assertEqual(len(flp.combinations_count), 0)

    def test_positve_case(self):
        flp = DefaultFlowLogsParser(2, "dummy", "dummy", "dummy")
        flp.table[6]="tcp"
        flp.tag_map[(49153, "tcp")] = "sv_P1"
        flp.tag_map[(49154, "tcp")] = "sv_P1"
        lines = [
            "2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK",
            "2 123456789012 eni-4d3c2b1a 192.168.1.100 203.0.113.101 23 49154 6 15 12000 1620140761 1620140821 REJECT OK",
            "",
            "2 123456789012 eni-5e6f7g8h 192.168.1.101 198.51.100.3 25 49155 6 10 8000 1620140761 1620140821 ACCEPT OK",
        ]

        flp._analyze_flow_logs(lines)
        self.assertTrue(flp.errors > 0)
        self.assertEqual(len(flp.tag_count), 2)
        self.assertEqual(len(flp.combinations_count), 3)
        self.assertEqual(flp.tag_count['Untagged'], 1)

if __name__ == "__main__":
    unittest.main()
