#!/usr/bin/env python3
"""
Security Validation Script for Splunk Security Alerts
Performs comprehensive security checks and generates compliance reports
"""

import os
import re
import sys
import json
import hashlib
import configparser
from datetime import datetime
from pathlib import Path
import subprocess
import csv

class SecurityValidator:
    """Main security validation class"""

    def __init__(self, app_path=None):
        """Initialize the security validator"""
        self.app_path = app_path or os.path.join(
            os.environ.get('SPLUNK_HOME', '/opt/splunk'),
            'etc', 'apps', 'security_alerts'
        )
        self.results = {
            'passed': [],
            'failed': [],
            'warnings': [],
            'info': []
        }
        self.score = 0
        self.max_score = 0

    def run_all_checks(self):
        """Run all security validation checks"""
        print("=" * 60)
        print("Splunk Security Alerts - Security Validation")
        print("=" * 60)
        print(f"Validating app at: {self.app_path}\n")

        # Run individual security checks
        self.check_file_permissions()
        self.check_sensitive_data()
        self.check_input_validation()
        self.check_authentication_security()
        self.check_encryption_settings()
        self.check_access_controls()
        self.check_logging_configuration()
        self.check_network_security()
        self.check_dependency_vulnerabilities()
        self.check_compliance_requirements()
        self.check_backup_recovery()
        self.check_monitoring_alerting()

        # Generate report
        self.generate_security_report()

        return self.calculate_security_score()

    def check_file_permissions(self):
        """Check file and directory permissions"""
        print("\n[*] Checking file permissions...")
        self.max_score += 10

        issues_found = 0
        files_checked = 0

        for root, dirs, files in os.walk(self.app_path):
            # Check directory permissions
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                try:
                    stat_info = os.stat(dir_path)
                    mode = oct(stat_info.st_mode)[-3:]

                    if mode not in ['755', '750', '700']:
                        self.results['warnings'].append(
                            f"Directory {dir_path} has permissive permissions: {mode}"
                        )
                        issues_found += 1
                except Exception as e:
                    self.results['failed'].append(f"Cannot check {dir_path}: {e}")

            # Check file permissions
            for file_name in files:
                file_path = os.path.join(root, file_name)
                files_checked += 1

                try:
                    stat_info = os.stat(file_path)
                    mode = oct(stat_info.st_mode)[-3:]

                    # Configuration files should not be world-writable
                    if mode[-1] in ['2', '3', '6', '7']:
                        self.results['failed'].append(
                            f"File {file_path} is world-writable: {mode}"
                        )
                        issues_found += 1

                    # Scripts should be executable only by owner
                    if file_name.endswith(('.sh', '.py')) and mode not in ['755', '750', '700']:
                        self.results['warnings'].append(
                            f"Script {file_path} has incorrect permissions: {mode}"
                        )
                        issues_found += 1

                except Exception as e:
                    self.results['failed'].append(f"Cannot check {file_path}: {e}")

        if issues_found == 0:
            self.results['passed'].append(f"All {files_checked} files have secure permissions")
            self.score += 10
        else:
            self.score += max(0, 10 - issues_found)

    def check_sensitive_data(self):
        """Check for hardcoded sensitive data"""
        print("[*] Checking for sensitive data...")
        self.max_score += 15

        sensitive_patterns = [
            (r'password\s*=\s*["\'](?!changeme|password|\*+)[^"\']+["\']', 'Hardcoded password'),
            (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', 'Hardcoded API key'),
            (r'secret\s*=\s*["\'][^"\']+["\']', 'Hardcoded secret'),
            (r'token\s*=\s*["\'][^"\']+["\']', 'Hardcoded token'),
            (r'admin:changeme', 'Default credentials'),
            (r'private[_-]?key\s*=\s*["\'][^"\']+["\']', 'Hardcoded private key'),
            (r'\b\d{3}-\d{2}-\d{4}\b', 'Potential SSN'),
            (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', 'Potential credit card')
        ]

        issues_found = 0
        files_scanned = 0

        for root, dirs, files in os.walk(self.app_path):
            # Skip .git directory
            if '.git' in root:
                continue

            for file_name in files:
                # Only check text files
                if not file_name.endswith(('.conf', '.py', '.sh', '.xml', '.csv', '.json')):
                    continue

                file_path = os.path.join(root, file_name)
                files_scanned += 1

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                        for pattern, description in sensitive_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            if matches:
                                self.results['failed'].append(
                                    f"{description} found in {file_path}: {len(matches)} occurrence(s)"
                                )
                                issues_found += 1

                except Exception as e:
                    self.results['warnings'].append(f"Cannot scan {file_path}: {e}")

        if issues_found == 0:
            self.results['passed'].append(f"No sensitive data found in {files_scanned} files")
            self.score += 15
        else:
            self.results['failed'].append(f"Found {issues_found} sensitive data issues")
            self.score += max(0, 15 - (issues_found * 3))

    def check_input_validation(self):
        """Check for input validation in searches"""
        print("[*] Checking input validation...")
        self.max_score += 15

        # Check saved searches for input validation
        savedsearches_path = os.path.join(self.app_path, 'default', 'savedsearches.conf')

        if not os.path.exists(savedsearches_path):
            self.results['failed'].append("savedsearches.conf not found")
            return

        config = configparser.ConfigParser()
        config.read(savedsearches_path)

        vulnerable_patterns = [
            (r'eval.*\$.*\$', 'Potential eval injection'),
            (r'rex.*\|.*\|', 'Potential regex injection'),
            (r'search\s+index=\*', 'Overly permissive index access'),
            (r'(?<!\\)\$(?!time)', 'Unescaped variable'),
            (r'`.*`', 'Potential command injection'),
            (r'\|\s*script', 'Script command usage'),
            (r'\|\s*run', 'Run command usage')
        ]

        issues_found = 0
        searches_checked = 0

        for section in config.sections():
            if 'search' in config[section]:
                search_query = config[section]['search']
                searches_checked += 1

                for pattern, description in vulnerable_patterns:
                    if re.search(pattern, search_query):
                        self.results['warnings'].append(
                            f"{description} in search '{section}'"
                        )
                        issues_found += 1

                # Check for proper field validation
                if 'src_ip' in search_query and 'regex src_ip=' not in search_query:
                    self.results['warnings'].append(
                        f"Search '{section}' uses src_ip without validation"
                    )
                    issues_found += 1

        if issues_found == 0:
            self.results['passed'].append(f"All {searches_checked} searches have proper input validation")
            self.score += 15
        else:
            self.results['warnings'].append(f"Found {issues_found} input validation issues")
            self.score += max(0, 15 - (issues_found * 2))

    def check_authentication_security(self):
        """Check authentication and session security settings"""
        print("[*] Checking authentication security...")
        self.max_score += 10

        security_settings = {
            'minPasswordLength': (12, 'Minimum password length'),
            'sessionTimeout': (900, 'Session timeout'),
            'lockoutAttempts': (5, 'Account lockout attempts'),
            'enablePasswordHistory': ('true', 'Password history'),
            'enableSplunkWebSSL': ('true', 'SSL/TLS enabled')
        }

        issues_found = 0

        # Check app.conf for security settings
        app_conf_path = os.path.join(self.app_path, 'default', 'app.conf')

        if os.path.exists(app_conf_path):
            config = configparser.ConfigParser()
            config.read(app_conf_path)

            for setting, (expected, description) in security_settings.items():
                found = False
                for section in config.sections():
                    if setting in config[section]:
                        value = config[section][setting]
                        found = True

                        if isinstance(expected, int):
                            if int(value) < expected:
                                self.results['warnings'].append(
                                    f"{description} is too low: {value} (minimum: {expected})"
                                )
                                issues_found += 1
                        elif value != expected:
                            self.results['warnings'].append(
                                f"{description} is not properly configured: {value}"
                            )
                            issues_found += 1

                if not found:
                    self.results['warnings'].append(f"{description} is not configured")
                    issues_found += 1

        if issues_found == 0:
            self.results['passed'].append("Authentication security properly configured")
            self.score += 10
        else:
            self.score += max(0, 10 - issues_found)

    def check_encryption_settings(self):
        """Check encryption configuration"""
        print("[*] Checking encryption settings...")
        self.max_score += 10

        encryption_checks = {
            'TLS Configuration': self.validate_tls_settings(),
            'Data Encryption': self.validate_data_encryption(),
            'Certificate Validation': self.validate_certificates()
        }

        passed = sum(1 for check in encryption_checks.values() if check)
        total = len(encryption_checks)

        if passed == total:
            self.results['passed'].append("All encryption settings properly configured")
            self.score += 10
        else:
            self.results['warnings'].append(f"Encryption issues: {total - passed} of {total} checks failed")
            self.score += int(10 * (passed / total))

    def validate_tls_settings(self):
        """Validate TLS configuration"""
        # Check for weak SSL/TLS versions
        weak_protocols = ['ssl2', 'ssl3', 'tls1.0', 'tls1.1']

        for root, dirs, files in os.walk(self.app_path):
            for file_name in files:
                if file_name.endswith('.conf'):
                    file_path = os.path.join(root, file_name)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read().lower()
                            for protocol in weak_protocols:
                                if protocol in content:
                                    self.results['failed'].append(
                                        f"Weak protocol {protocol} referenced in {file_path}"
                                    )
                                    return False
                    except:
                        pass
        return True

    def validate_data_encryption(self):
        """Validate data encryption settings"""
        # Check if sensitive data is encrypted
        required_encryption = ['encrypt_lookups', 'encrypt_kvstore']
        found_encryption = []

        for root, dirs, files in os.walk(self.app_path):
            for file_name in files:
                if file_name.endswith('.conf'):
                    file_path = os.path.join(root, file_name)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            for setting in required_encryption:
                                if f"{setting} = true" in content:
                                    found_encryption.append(setting)
                    except:
                        pass

        return len(found_encryption) >= len(required_encryption) // 2

    def validate_certificates(self):
        """Validate certificate settings"""
        # Check for certificate validation
        cert_settings = ['requireClientCert', 'sslVerifyServerCert']
        found_settings = []

        for root, dirs, files in os.walk(self.app_path):
            for file_name in files:
                if file_name.endswith('.conf'):
                    file_path = os.path.join(root, file_name)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            for setting in cert_settings:
                                if f"{setting} = true" in content:
                                    found_settings.append(setting)
                    except:
                        pass

        return len(found_settings) > 0

    def check_access_controls(self):
        """Check access control configuration"""
        print("[*] Checking access controls...")
        self.max_score += 10

        # Check metadata for proper access controls
        metadata_path = os.path.join(self.app_path, 'metadata', 'default.meta')

        if not os.path.exists(metadata_path):
            self.results['warnings'].append("metadata/default.meta not found")
            self.score += 5
            return

        try:
            with open(metadata_path, 'r') as f:
                content = f.read()

                # Check for overly permissive access
                if 'write : [ * ]' in content:
                    self.results['failed'].append("Overly permissive write access in metadata")
                elif 'write : [ admin' in content:
                    self.results['passed'].append("Access controls properly restricted to admin")
                    self.score += 10
                else:
                    self.results['warnings'].append("Unclear access control configuration")
                    self.score += 5

        except Exception as e:
            self.results['failed'].append(f"Cannot read metadata: {e}")

    def check_logging_configuration(self):
        """Check logging and audit configuration"""
        print("[*] Checking logging configuration...")
        self.max_score += 5

        required_logging = [
            'audit_all_searches',
            'audit_all_changes',
            'audit_all_access'
        ]

        found_settings = 0
        for root, dirs, files in os.walk(self.app_path):
            for file_name in files:
                if file_name.endswith('.conf'):
                    file_path = os.path.join(root, file_name)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            for setting in required_logging:
                                if f"{setting} = true" in content:
                                    found_settings += 1
                    except:
                        pass

        if found_settings >= len(required_logging):
            self.results['passed'].append("Comprehensive logging configured")
            self.score += 5
        elif found_settings > 0:
            self.results['warnings'].append(f"Partial logging configured ({found_settings}/{len(required_logging)})")
            self.score += 3
        else:
            self.results['failed'].append("Audit logging not configured")

    def check_network_security(self):
        """Check network security settings"""
        print("[*] Checking network security...")
        self.max_score += 5

        network_issues = []

        # Check for IP whitelisting
        if not self.check_ip_whitelisting():
            network_issues.append("IP whitelisting not configured")

        # Check for blocked ports
        if not self.check_port_restrictions():
            network_issues.append("Port restrictions not configured")

        if len(network_issues) == 0:
            self.results['passed'].append("Network security properly configured")
            self.score += 5
        else:
            for issue in network_issues:
                self.results['warnings'].append(issue)
            self.score += max(0, 5 - len(network_issues))

    def check_ip_whitelisting(self):
        """Check if IP whitelisting is configured"""
        authorized_ips_path = os.path.join(self.app_path, 'lookups', 'authorized_ips.csv')
        return os.path.exists(authorized_ips_path) and os.path.getsize(authorized_ips_path) > 100

    def check_port_restrictions(self):
        """Check if port restrictions are configured"""
        # Check for dangerous port references
        dangerous_ports = ['23', '135', '139', '445', '3389']

        for root, dirs, files in os.walk(self.app_path):
            for file_name in files:
                if file_name.endswith('.conf'):
                    file_path = os.path.join(root, file_name)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            for port in dangerous_ports:
                                if f"port {port}" in content or f":{port}" in content:
                                    self.results['warnings'].append(
                                        f"Dangerous port {port} referenced in {file_path}"
                                    )
                                    return False
                    except:
                        pass
        return True

    def check_dependency_vulnerabilities(self):
        """Check for known vulnerabilities in dependencies"""
        print("[*] Checking dependency vulnerabilities...")
        self.max_score += 10

        # Check Python dependencies if requirements.txt exists
        requirements_path = os.path.join(self.app_path, 'requirements.txt')

        if os.path.exists(requirements_path):
            try:
                # Try to run safety check if available
                result = subprocess.run(
                    ['safety', 'check', '--file', requirements_path, '--json'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    vulnerabilities = json.loads(result.stdout)
                    if len(vulnerabilities) == 0:
                        self.results['passed'].append("No known vulnerabilities in dependencies")
                        self.score += 10
                    else:
                        self.results['failed'].append(
                            f"Found {len(vulnerabilities)} vulnerable dependencies"
                        )
                        for vuln in vulnerabilities[:5]:  # Show first 5
                            self.results['failed'].append(
                                f"  - {vuln.get('package', 'Unknown')}: {vuln.get('vulnerability', 'Unknown')}"
                            )
            except:
                self.results['info'].append("Dependency scanning not available")
                self.score += 5
        else:
            self.results['info'].append("No Python dependencies file found")
            self.score += 10

    def check_compliance_requirements(self):
        """Check compliance with security standards"""
        print("[*] Checking compliance requirements...")
        self.max_score += 10

        compliance_checks = {
            'GDPR': self.check_gdpr_compliance(),
            'PCI-DSS': self.check_pci_compliance(),
            'HIPAA': self.check_hipaa_compliance()
        }

        passed = sum(1 for check in compliance_checks.values() if check)
        total = len(compliance_checks)

        if passed == total:
            self.results['passed'].append("All compliance requirements met")
            self.score += 10
        else:
            self.results['info'].append(f"Compliance: {passed} of {total} standards met")
            self.score += int(10 * (passed / total))

    def check_gdpr_compliance(self):
        """Check GDPR compliance requirements"""
        gdpr_requirements = ['data_retention', 'pii_handling', 'right_to_erasure']
        found = 0

        for req in gdpr_requirements:
            for root, dirs, files in os.walk(self.app_path):
                for file_name in files:
                    if file_name.endswith('.conf'):
                        file_path = os.path.join(root, file_name)
                        try:
                            with open(file_path, 'r') as f:
                                if req in f.read():
                                    found += 1
                                    break
                        except:
                            pass

        return found >= 2

    def check_pci_compliance(self):
        """Check PCI-DSS compliance requirements"""
        pci_requirements = ['encrypt', 'mask', 'audit']
        found = 0

        for req in pci_requirements:
            for root, dirs, files in os.walk(self.app_path):
                for file_name in files:
                    if file_name.endswith('.conf'):
                        file_path = os.path.join(root, file_name)
                        try:
                            with open(file_path, 'r') as f:
                                if req in f.read().lower():
                                    found += 1
                                    break
                        except:
                            pass

        return found >= 2

    def check_hipaa_compliance(self):
        """Check HIPAA compliance requirements"""
        # Basic check for HIPAA-related configurations
        return self.check_pci_compliance()  # Similar requirements

    def check_backup_recovery(self):
        """Check backup and recovery configuration"""
        print("[*] Checking backup and recovery...")
        self.max_score += 5

        backup_configured = False
        recovery_configured = False

        for root, dirs, files in os.walk(self.app_path):
            for file_name in files:
                if file_name.endswith('.conf'):
                    file_path = os.path.join(root, file_name)
                    try:
                        with open(file_path, 'r') as f:
                            content = f.read()
                            if 'backup' in content.lower():
                                backup_configured = True
                            if 'recovery' in content.lower():
                                recovery_configured = True
                    except:
                        pass

        if backup_configured and recovery_configured:
            self.results['passed'].append("Backup and recovery configured")
            self.score += 5
        elif backup_configured or recovery_configured:
            self.results['warnings'].append("Partial backup/recovery configuration")
            self.score += 3
        else:
            self.results['failed'].append("No backup/recovery configuration found")

    def check_monitoring_alerting(self):
        """Check monitoring and alerting configuration"""
        print("[*] Checking monitoring and alerting...")
        self.max_score += 5

        # Check if critical alerts are configured
        savedsearches_path = os.path.join(self.app_path, 'default', 'savedsearches.conf')

        if os.path.exists(savedsearches_path):
            config = configparser.ConfigParser()
            config.read(savedsearches_path)

            critical_alerts = 0
            high_alerts = 0

            for section in config.sections():
                if 'alert.severity' in config[section]:
                    severity = config[section]['alert.severity']
                    if severity == '5':
                        critical_alerts += 1
                    elif severity == '4':
                        high_alerts += 1

            if critical_alerts >= 3 and high_alerts >= 3:
                self.results['passed'].append(
                    f"Comprehensive alerting configured: {critical_alerts} critical, {high_alerts} high"
                )
                self.score += 5
            else:
                self.results['warnings'].append(
                    f"Limited alerting: {critical_alerts} critical, {high_alerts} high"
                )
                self.score += 3
        else:
            self.results['failed'].append("No saved searches configured")

    def calculate_security_score(self):
        """Calculate overall security score"""
        if self.max_score > 0:
            percentage = (self.score / self.max_score) * 100
        else:
            percentage = 0

        grade = 'F'
        if percentage >= 90:
            grade = 'A'
        elif percentage >= 80:
            grade = 'B'
        elif percentage >= 70:
            grade = 'C'
        elif percentage >= 60:
            grade = 'D'

        return {
            'score': self.score,
            'max_score': self.max_score,
            'percentage': percentage,
            'grade': grade
        }

    def generate_security_report(self):
        """Generate comprehensive security report"""
        print("\n" + "=" * 60)
        print("SECURITY VALIDATION REPORT")
        print("=" * 60)

        # Calculate score
        score_data = self.calculate_security_score()

        print(f"\nSecurity Score: {score_data['score']}/{score_data['max_score']} ({score_data['percentage']:.1f}%)")
        print(f"Grade: {score_data['grade']}")

        # Print results by category
        if self.results['passed']:
            print(f"\n✅ PASSED ({len(self.results['passed'])} checks)")
            for item in self.results['passed']:
                print(f"  ✓ {item}")

        if self.results['failed']:
            print(f"\n❌ FAILED ({len(self.results['failed'])} checks)")
            for item in self.results['failed']:
                print(f"  ✗ {item}")

        if self.results['warnings']:
            print(f"\n⚠️  WARNINGS ({len(self.results['warnings'])} items)")
            for item in self.results['warnings']:
                print(f"  ⚠ {item}")

        if self.results['info']:
            print(f"\nℹ️  INFORMATION ({len(self.results['info'])} items)")
            for item in self.results['info']:
                print(f"  ℹ {item}")

        # Save report to file
        report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = os.path.join(os.path.dirname(self.app_path), report_file)

        report_data = {
            'timestamp': datetime.now().isoformat(),
            'app_path': self.app_path,
            'score': score_data,
            'results': self.results
        }

        try:
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            print(f"\n📄 Report saved to: {report_path}")
        except Exception as e:
            print(f"\n⚠️  Could not save report: {e}")

        print("\n" + "=" * 60)

        # Return exit code based on grade
        if score_data['grade'] in ['A', 'B']:
            return 0
        elif score_data['grade'] == 'C':
            return 1
        else:
            return 2


def main():
    """Main execution function"""
    # Parse command line arguments
    app_path = None
    if len(sys.argv) > 1:
        app_path = sys.argv[1]

    # Create and run validator
    validator = SecurityValidator(app_path)
    exit_code = validator.run_all_checks()

    sys.exit(exit_code)


if __name__ == "__main__":
    main()