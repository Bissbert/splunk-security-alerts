#!/usr/bin/env python3
"""Unit tests for the SPL checks in tests/test_searches.py."""

import contextlib
import io
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_searches import SearchTester, scan_spl  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CONF = ROOT / 'security_alerts_app' / 'default' / 'savedsearches.conf'


def tester():
    return SearchTester(CONF)


class ScanSplTest(unittest.TestCase):
    def test_drops_quoted_text(self):
        self.assertEqual(scan_spl('a "b[c" d'), ('a  d', False))

    def test_escaped_quote_stays_inside_string(self):
        self.assertEqual(scan_spl(r'x="a\"[" y'), ('x= y', False))

    def test_escaped_bracket_in_regex(self):
        outside, open_quote = scan_spl(r'rex "su\\[.*success" | stats count')
        self.assertNotIn('[', outside)
        self.assertFalse(open_quote)

    def test_reports_open_quote(self):
        self.assertTrue(scan_spl('search a="b')[1])


class SyntaxCheckTest(unittest.TestCase):
    def check(self, query):
        t = tester()
        return t.validate_search_syntax('s', query), t.errors

    def test_valid_search(self):
        self.assertEqual(self.check('index=main | stats count by host'), (True, []))

    def test_bracket_inside_quoted_regex_is_valid(self):
        # Entry 4 / issue #5: the Privilege Escalation regex.
        ok, errors = self.check(r'index=* | regex _raw="su\\[.*authentication success"')
        self.assertTrue(ok, errors)

    def test_paren_inside_quoted_string_is_valid(self):
        ok, errors = self.check('index=* | search msg="smile :)"')
        self.assertTrue(ok, errors)

    def test_subsearch_brackets_are_valid(self):
        ok, errors = self.check('index=* [search index=b | fields host] | stats count')
        self.assertTrue(ok, errors)

    def test_unbalanced_subsearch_bracket(self):
        ok, errors = self.check('index=* [search index=b | stats count')
        self.assertFalse(ok)
        self.assertEqual(errors, ['s: Unbalanced square brackets'])

    def test_close_before_open(self):
        ok, errors = self.check('index=* | eval x=)a(')
        self.assertFalse(ok)
        self.assertEqual(errors, ['s: Unbalanced parentheses'])

    def test_unterminated_quote(self):
        ok, errors = self.check('index=* | search a="b')
        self.assertFalse(ok)
        self.assertIn('s: Unbalanced quotes in search', errors)

    def test_empty_search(self):
        ok, errors = self.check('')
        self.assertFalse(ok)
        self.assertEqual(errors, ['s: Empty search query'])

    def test_missing_index_warns(self):
        t = tester()
        self.assertTrue(t.validate_search_syntax('s', 'search foo | stats count'))
        self.assertIn('s: No index specified (may impact performance)', t.warnings)


class PerSearchResultTest(unittest.TestCase):
    def test_later_search_passes_after_an_earlier_error(self):
        # Entry 3 / issue #4: errors from one search must not fail the next.
        t = tester()
        self.assertFalse(t.validate_search_syntax('bad', 'index=* | eval x=(1'))
        self.assertTrue(t.validate_search_syntax('good', 'index=* | stats count'))
        self.assertEqual(t.errors, ['bad: Unbalanced parentheses'])


class ConfigRunTest(unittest.TestCase):
    def run_conf(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / 'default' / 'savedsearches.conf'
            conf.parent.mkdir()
            (Path(tmp) / 'lookups').mkdir()
            (Path(tmp) / 'lookups' / 'known.csv').write_text('a,b\n')
            conf.write_text(textwrap.dedent(text))
            t = SearchTester(conf)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = t.run_tests()
            return rc, out.getvalue(), t

    GOOD = '''
        [Good]
        search = index=main | lookup known.csv a OUTPUT b | stats count
        description = d
        cron_schedule = */5 * * * *
        alert.severity = 3
        '''

    def test_valid_config_exits_0(self):
        rc, out, t = self.run_conf(self.GOOD)
        self.assertEqual(rc, 0)
        self.assertIn('Valid searches: 1', out)
        self.assertEqual(t.warnings, [])

    def test_counts_only_the_broken_search(self):
        rc, out, _ = self.run_conf('''
            [Broken]
            search = index=main | eval x=(1
            description = d
            cron_schedule = * * * * *
            ''' + self.GOOD)
        self.assertEqual(rc, 1)
        self.assertIn('Total searches: 2', out)
        self.assertIn('Valid searches: 1', out)
        self.assertIn('Errors: 1', out)

    def test_missing_fields_and_bad_cron(self):
        rc, _, t = self.run_conf('''
            [NoFields]
            search = index=main
            cron_schedule = every five minutes
            ''')
        self.assertEqual(rc, 1)
        self.assertIn("NoFields: Missing required field 'description'", t.errors)
        self.assertIn('NoFields: Invalid cron schedule format', t.errors)

    def test_bad_severity_and_missing_lookup_warn(self):
        rc, _, t = self.run_conf('''
            [Warn]
            search = index=main | lookup absent.csv a OUTPUT b
            description = d
            cron_schedule = 0 * * * *
            alert.severity = 9
            ''')
        self.assertEqual(rc, 0)
        self.assertIn('Warn: Invalid alert severity (should be 1-5)', t.warnings)
        self.assertIn('Lookup file not found: absent.csv', t.warnings)


class ShippedConfigTest(unittest.TestCase):
    def test_all_shipped_searches_are_valid(self):
        t = tester()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = t.run_tests()
        self.assertEqual(t.errors, [])
        self.assertEqual(rc, 0)
        self.assertIn('Total searches: 13', out.getvalue())
        self.assertIn('Valid searches: 13', out.getvalue())


if __name__ == '__main__':
    unittest.main()
