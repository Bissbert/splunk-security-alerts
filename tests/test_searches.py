#!/usr/bin/env python3
"""
Test suite for Splunk security alert searches
Validates search syntax and configuration
"""

import re
import sys
import configparser
from pathlib import Path

class SearchTester:
    def __init__(self, config_path):
        self.config_path = Path(config_path)
        self.errors = []
        self.warnings = []

    def load_config(self):
        """Load savedsearches.conf file"""
        config = configparser.ConfigParser()
        config.read(self.config_path)
        return config

    def validate_search_syntax(self, search_name, search_query):
        """Validate SPL syntax basics"""
        # Check for common syntax issues
        if not search_query:
            self.errors.append(f"{search_name}: Empty search query")
            return False

        # Check for balanced quotes
        if search_query.count('"') % 2 != 0:
            self.errors.append(f"{search_name}: Unbalanced quotes in search")

        # Check for balanced parentheses
        if search_query.count('(') != search_query.count(')'):
            self.errors.append(f"{search_name}: Unbalanced parentheses")

        # Check for balanced square brackets
        if search_query.count('[') != search_query.count(']'):
            self.errors.append(f"{search_name}: Unbalanced square brackets")

        # Check for required index specification
        if not re.search(r'index\s*=', search_query):
            self.warnings.append(f"{search_name}: No index specified (may impact performance)")

        # Check for time range
        if 'earliest' not in search_query and 'latest' not in search_query:
            if 'bin _time' in search_query or 'timechart' in search_query:
                self.warnings.append(f"{search_name}: Time-based command without explicit time range")

        return len(self.errors) == 0

    def validate_required_fields(self, search_name, config_section):
        """Validate required configuration fields"""
        required_fields = ['search', 'description', 'cron_schedule']

        for field in required_fields:
            if field not in config_section:
                self.errors.append(f"{search_name}: Missing required field '{field}'")

        # Validate cron schedule format
        if 'cron_schedule' in config_section:
            cron = config_section['cron_schedule']
            # Basic cron validation
            if not re.match(r'^(\*|[0-9,\-*/]+)\s+(\*|[0-9,\-*/]+)\s+(\*|[0-9,\-*/]+)\s+(\*|[0-9,\-*/]+)\s+(\*|[0-9,\-*/]+)$', cron):
                self.errors.append(f"{search_name}: Invalid cron schedule format")

    def validate_lookups(self, search_query):
        """Check if referenced lookups exist"""
        lookup_pattern = r'lookup\s+(\w+\.csv)'
        lookups = re.findall(lookup_pattern, search_query)

        lookups_dir = self.config_path.parent.parent / 'lookups'

        for lookup in lookups:
            lookup_path = lookups_dir / lookup
            if not lookup_path.exists():
                self.warnings.append(f"Lookup file not found: {lookup}")

    def run_tests(self):
        """Run all validation tests"""
        print("=" * 60)
        print("Splunk Security Alerts - Search Validation")
        print("=" * 60)

        config = self.load_config()

        total_searches = 0
        valid_searches = 0

        for section in config.sections():
            if section == 'DEFAULT':
                continue

            total_searches += 1
            print(f"\nValidating: {section}")

            # Get search query
            if 'search' in config[section]:
                search_query = config[section]['search']

                # Validate syntax
                if self.validate_search_syntax(section, search_query):
                    print(f"  ✓ Search syntax valid")
                    valid_searches += 1
                else:
                    print(f"  ✗ Search syntax errors found")

                # Validate lookups
                self.validate_lookups(search_query)

            # Validate required fields
            self.validate_required_fields(section, config[section])

            # Check alert configuration
            if 'alert.severity' in config[section]:
                severity = config[section]['alert.severity']
                if severity not in ['1', '2', '3', '4', '5']:
                    self.warnings.append(f"{section}: Invalid alert severity (should be 1-5)")

        # Print summary
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Total searches: {total_searches}")
        print(f"Valid searches: {valid_searches}")
        print(f"Errors: {len(self.errors)}")
        print(f"Warnings: {len(self.warnings)}")

        if self.errors:
            print("\n" + "=" * 60)
            print("ERRORS")
            print("=" * 60)
            for error in self.errors:
                print(f"  ✗ {error}")

        if self.warnings:
            print("\n" + "=" * 60)
            print("WARNINGS")
            print("=" * 60)
            for warning in self.warnings:
                print(f"  ⚠ {warning}")

        print("\n" + "=" * 60)

        # Return exit code
        return 0 if len(self.errors) == 0 else 1

def main():
    config_path = Path(__file__).parent.parent / 'default' / 'savedsearches.conf'

    if not config_path.exists():
        print(f"Error: Configuration file not found at {config_path}")
        sys.exit(1)

    tester = SearchTester(config_path)
    exit_code = tester.run_tests()
    sys.exit(exit_code)

if __name__ == "__main__":
    main()