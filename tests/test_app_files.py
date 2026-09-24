#!/usr/bin/env python3
"""Checks on the shipped app files that need no Splunk instance."""

import configparser
import csv
import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'security_alerts_app'
DEFAULT = APP / 'default'
LOOKUPS = APP / 'lookups'


def conf(name):
    parser = configparser.RawConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read(DEFAULT / name, encoding='utf-8')
    return parser


class SavedSearchesTest(unittest.TestCase):
    def setUp(self):
        self.searches = conf('savedsearches.conf')

    def test_thirteen_searches(self):
        self.assertEqual(len(self.searches.sections()), 13)

    def test_lookups_used_by_searches_are_shipped(self):
        for name in self.searches.sections():
            for lookup in re.findall(r'lookup\s+(\w+\.csv)', self.searches[name]['search']):
                with self.subTest(search=name, lookup=lookup):
                    self.assertTrue((LOOKUPS / lookup).is_file())

    def test_severity_and_dispatch_window(self):
        for name in self.searches.sections():
            s = self.searches[name]
            with self.subTest(search=name):
                self.assertIn(s.get('alert.severity'), {'1', '2', '3', '4', '5'})
                self.assertTrue(s.get('dispatch.earliest_time', '').startswith('-'))

    def test_suppression_fields_are_set(self):
        for name in self.searches.sections():
            s = self.searches[name]
            if s.get('alert.suppress') == '1':
                with self.subTest(search=name):
                    self.assertTrue(s.get('alert.suppress.fields'))


class LookupFilesTest(unittest.TestCase):
    def test_every_csv_has_a_header_and_even_rows(self):
        for path in sorted(LOOKUPS.glob('*.csv')):
            with self.subTest(lookup=path.name):
                with path.open(newline='', encoding='utf-8') as handle:
                    rows = list(csv.reader(handle))
                self.assertTrue(rows and rows[0])
                self.assertEqual({len(r) for r in rows if r}, {len(rows[0])})

    def test_search_lookup_fields_exist_in_the_csv(self):
        # Issue #6: Splunk rejects a lookup whose match field is not a column.
        pattern = re.compile(
            r'lookup\s+(\w+\.csv)\s+(\w+)(?:\s+AS\s+\w+)?(?:=\w+)?\s+OUTPUT\s+([\w,\s]+?)\s*(?:\||$)')
        searches = conf('savedsearches.conf')
        seen = 0
        for name in searches.sections():
            for lookup, key, output in pattern.findall(searches[name]['search']):
                seen += 1
                header = (LOOKUPS / lookup).read_text(encoding='utf-8').splitlines()[0].split(',')
                for field in [key] + re.split(r'[,\s]+', output.strip()):
                    with self.subTest(search=name, lookup=lookup, field=field):
                        self.assertIn(field, header)
        self.assertEqual(seen, 10)


class DashboardsTest(unittest.TestCase):
    def test_dashboards_parse(self):
        views = sorted((DEFAULT / 'data' / 'ui' / 'views').glob('*.xml'))
        self.assertEqual(len(views), 2)
        for path in views:
            with self.subTest(view=path.name):
                self.assertGreater(len(ET.parse(path).getroot().findall('.//panel')), 0)


class ConfFilesTest(unittest.TestCase):
    def test_conf_files_parse(self):
        for path in sorted(DEFAULT.glob('*.conf')):
            with self.subTest(conf=path.name):
                conf(path.name)


if __name__ == '__main__':
    unittest.main()
