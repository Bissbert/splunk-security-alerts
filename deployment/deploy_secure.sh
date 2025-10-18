#!/bin/bash

# Splunk Security Alerts Deployment Script - Secure Version
# Enhanced with security best practices and hardening measures

set -euo pipefail
IFS=$'\n\t'

# Enable strict error handling
trap 'error_handler $? $LINENO' ERR

# Security Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly APP_ROOT="$(dirname "$SCRIPT_DIR")"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly LOG_FILE="/var/log/splunk_deploy_${TIMESTAMP}.log"
readonly CHECKSUM_FILE="${APP_ROOT}/.security/checksums.sha256"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Default values
SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
APP_NAME="${APP_NAME:-security_alerts}"
RESTART_SPLUNK="${RESTART_SPLUNK:-yes}"
VERIFY_CHECKSUMS="${VERIFY_CHECKSUMS:-yes}"
BACKUP_ENABLED="${BACKUP_ENABLED:-yes}"
SECURE_MODE="${SECURE_MODE:-yes}"

# Security settings
umask 077  # Restrictive file permissions by default
REQUIRED_SPLUNK_VERSION="8.2.0"
MAX_BACKUP_SIZE="1073741824"  # 1GB max backup size

# Error handler function
error_handler() {
    local exit_code=$1
    local line_number=$2
    print_msg "$RED" "ERROR: Command failed with exit code $exit_code at line $line_number"
    print_msg "$RED" "Check log file: $LOG_FILE"
    exit "$exit_code"
}

# Logging function
log_message() {
    local level=$1
    shift
    local message="$*"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" | tee -a "$LOG_FILE"
}

# Function to print colored output
print_msg() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
    log_message "INFO" "$message"
}

# Security validation function
validate_security() {
    print_msg "$YELLOW" "Performing security validation..."

    # Check if running as root (should not be)
    if [[ $EUID -eq 0 ]]; then
        print_msg "$RED" "Security Error: This script should not be run as root!"
        log_message "ERROR" "Script executed as root - aborting for security"
        exit 1
    fi

    # Validate Splunk home directory
    if [[ ! -d "$SPLUNK_HOME" ]]; then
        print_msg "$RED" "Splunk home directory not found at $SPLUNK_HOME"
        exit 1
    fi

    # Check Splunk directory ownership
    local splunk_owner
    splunk_owner=$(stat -c '%U' "$SPLUNK_HOME" 2>/dev/null || stat -f '%Su' "$SPLUNK_HOME" 2>/dev/null)
    if [[ "$splunk_owner" != "$(whoami)" ]] && [[ "$splunk_owner" != "splunk" ]]; then
        print_msg "$YELLOW" "Warning: Splunk directory owned by $splunk_owner, current user is $(whoami)"
        log_message "WARN" "Ownership mismatch detected"
    fi

    # Verify Splunk version
    if [[ -x "$SPLUNK_HOME/bin/splunk" ]]; then
        local splunk_version
        splunk_version=$("$SPLUNK_HOME/bin/splunk" version 2>/dev/null | grep "Splunk" | awk '{print $2}' || echo "0.0.0")
        if ! version_compare "$splunk_version" "$REQUIRED_SPLUNK_VERSION"; then
            print_msg "$YELLOW" "Warning: Splunk version $splunk_version is older than recommended $REQUIRED_SPLUNK_VERSION"
            log_message "WARN" "Splunk version check: $splunk_version < $REQUIRED_SPLUNK_VERSION"
        fi
    fi

    print_msg "$GREEN" "Security validation completed"
}

# Version comparison function
version_compare() {
    local version1=$1
    local version2=$2

    if [[ "$version1" == "$version2" ]]; then
        return 0
    fi

    local IFS=.
    local i ver1=($version1) ver2=($version2)

    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do
        ver1[i]=0
    done

    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then
            ver2[i]=0
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then
            return 1
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then
            return 0
        fi
    done

    return 0
}

# Function to check prerequisites
check_prerequisites() {
    print_msg "$YELLOW" "Checking prerequisites..."

    # Check required commands
    local required_commands=("sha256sum" "tar" "find" "grep")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            print_msg "$RED" "Required command '$cmd' not found!"
            exit 1
        fi
    done

    # Check disk space
    local available_space
    available_space=$(df "$SPLUNK_HOME" | awk 'NR==2 {print $4}')
    if [[ $available_space -lt 1048576 ]]; then  # Less than 1GB
        print_msg "$RED" "Insufficient disk space in $SPLUNK_HOME"
        exit 1
    fi

    # Verify source files integrity
    if [[ "$VERIFY_CHECKSUMS" == "yes" ]]; then
        verify_file_integrity
    fi

    print_msg "$GREEN" "Prerequisites check passed!"
}

# Function to verify file integrity
verify_file_integrity() {
    print_msg "$YELLOW" "Verifying file integrity..."

    # Create .security directory if it doesn't exist
    mkdir -p "${APP_ROOT}/.security"
    chmod 700 "${APP_ROOT}/.security"

    if [[ ! -f "$CHECKSUM_FILE" ]]; then
        print_msg "$YELLOW" "Checksum file not found, generating..."
        generate_checksums
    else
        print_msg "$BLUE" "Validating file checksums..."
        local validation_output
        if validation_output=$(cd "$APP_ROOT" && sha256sum -c "$CHECKSUM_FILE" 2>&1); then
            print_msg "$GREEN" "File integrity verification passed"
            log_message "INFO" "Checksum validation successful"
        else
            print_msg "$RED" "File integrity verification failed!"
            echo "$validation_output" | tee -a "$LOG_FILE"
            print_msg "$YELLOW" "Regenerate checksums? (y/n)"
            read -r response
            if [[ "$response" == "y" ]]; then
                generate_checksums
            else
                exit 1
            fi
        fi
    fi
}

# Function to generate checksums
generate_checksums() {
    print_msg "$YELLOW" "Generating file checksums..."

    cd "$APP_ROOT"
    find . -type f \( -name "*.conf" -o -name "*.xml" -o -name "*.csv" -o -name "*.py" -o -name "*.sh" \) \
        -not -path "./.git/*" -not -path "./.security/*" \
        -exec sha256sum {} \; > "$CHECKSUM_FILE"

    chmod 600 "$CHECKSUM_FILE"
    print_msg "$GREEN" "Checksums generated successfully"
    log_message "INFO" "Generated checksums for $(wc -l < "$CHECKSUM_FILE") files"
}

# Function to backup existing app
backup_existing() {
    local app_path="$SPLUNK_HOME/etc/apps/$APP_NAME"

    if [[ -d "$app_path" ]] && [[ "$BACKUP_ENABLED" == "yes" ]]; then
        print_msg "$YELLOW" "Backing up existing app..."

        local backup_dir="$SPLUNK_HOME/etc/apps/.backups"
        mkdir -p "$backup_dir"
        chmod 700 "$backup_dir"

        local backup_name="${APP_NAME}_backup_${TIMESTAMP}.tar.gz"
        local backup_path="$backup_dir/$backup_name"

        # Create compressed backup
        tar -czf "$backup_path" -C "$SPLUNK_HOME/etc/apps" "$APP_NAME" 2>/dev/null

        # Verify backup
        if [[ -f "$backup_path" ]]; then
            local backup_size
            backup_size=$(stat -c%s "$backup_path" 2>/dev/null || stat -f%z "$backup_path" 2>/dev/null)

            if [[ $backup_size -gt $MAX_BACKUP_SIZE ]]; then
                print_msg "$YELLOW" "Warning: Backup size ($backup_size bytes) exceeds limit"
                log_message "WARN" "Large backup created: $backup_size bytes"
            fi

            chmod 600 "$backup_path"
            print_msg "$GREEN" "Backup created: $backup_path"
            log_message "INFO" "Backup created successfully: $backup_path"

            # Clean old backups (keep last 5)
            clean_old_backups "$backup_dir"
        else
            print_msg "$RED" "Failed to create backup!"
            exit 1
        fi
    fi
}

# Function to clean old backups
clean_old_backups() {
    local backup_dir=$1
    local max_backups=5

    local backup_count
    backup_count=$(find "$backup_dir" -name "${APP_NAME}_backup_*.tar.gz" | wc -l)

    if [[ $backup_count -gt $max_backups ]]; then
        print_msg "$YELLOW" "Cleaning old backups (keeping last $max_backups)..."
        find "$backup_dir" -name "${APP_NAME}_backup_*.tar.gz" -printf '%T+ %p\n' | \
            sort | head -n -"$max_backups" | cut -d' ' -f2- | \
            xargs -r rm -f
        log_message "INFO" "Cleaned old backups, kept $max_backups most recent"
    fi
}

# Function to securely read credentials
read_credentials() {
    local username password

    print_msg "$YELLOW" "Enter Splunk admin credentials for verification:"

    # Read username
    read -r -p "Username: " username

    # Read password securely (no echo)
    read -r -s -p "Password: " password
    echo

    # Export for use in verification (temporary)
    export SPLUNK_AUTH="${username}:${password}"

    # Schedule cleanup on exit
    trap 'unset SPLUNK_AUTH' EXIT
}

# Function to deploy the app
deploy_app() {
    print_msg "$YELLOW" "Deploying security alerts app..."

    local app_path="$SPLUNK_HOME/etc/apps/$APP_NAME"

    # Remove existing app directory if it exists
    if [[ -d "$app_path" ]]; then
        rm -rf "$app_path"
    fi

    # Create app directory structure with secure permissions
    mkdir -p "$app_path"/{default,local,lookups,metadata,bin}
    chmod 755 "$app_path"
    chmod 755 "$app_path"/{default,local,lookups,metadata,bin}

    # Copy configuration files with validation
    print_msg "$BLUE" "Copying configuration files..."

    # Copy and validate each configuration file
    for conf_file in "$APP_ROOT"/security_alerts_app/default/*.conf; do
        if [[ -f "$conf_file" ]]; then
            local filename=$(basename "$conf_file")
            cp "$conf_file" "$app_path/default/"
            chmod 644 "$app_path/default/$filename"

            # Validate configuration syntax
            if ! validate_conf_syntax "$app_path/default/$filename"; then
                print_msg "$RED" "Invalid configuration in $filename"
                exit 1
            fi
        fi
    done

    # Copy lookups with validation
    if [[ -d "$APP_ROOT/security_alerts_app/lookups" ]]; then
        print_msg "$BLUE" "Copying lookup files..."
        for lookup_file in "$APP_ROOT"/security_alerts_app/lookups/*.csv; do
            if [[ -f "$lookup_file" ]]; then
                local filename=$(basename "$lookup_file")
                cp "$lookup_file" "$app_path/lookups/"
                chmod 644 "$app_path/lookups/$filename"

                # Validate CSV format
                if ! validate_csv "$app_path/lookups/$filename"; then
                    print_msg "$YELLOW" "Warning: Invalid CSV format in $filename"
                fi
            fi
        done
    fi

    # Copy dashboards
    if [[ -d "$APP_ROOT/security_alerts_app/default/data/ui/views" ]]; then
        print_msg "$BLUE" "Copying dashboard files..."
        mkdir -p "$app_path/default/data/ui/views"
        for dashboard in "$APP_ROOT"/security_alerts_app/default/data/ui/views/*.xml; do
            if [[ -f "$dashboard" ]]; then
                local filename=$(basename "$dashboard")
                cp "$dashboard" "$app_path/default/data/ui/views/"
                chmod 644 "$app_path/default/data/ui/views/$filename"

                # Validate XML
                if command -v xmllint &> /dev/null; then
                    if ! xmllint --noout "$app_path/default/data/ui/views/$filename" 2>/dev/null; then
                        print_msg "$YELLOW" "Warning: Invalid XML in $filename"
                    fi
                fi
            fi
        done
    fi

    # Create secure app.conf
    create_secure_app_conf "$app_path"

    # Create metadata with security restrictions
    create_secure_metadata "$app_path"

    # Set proper ownership
    if [[ -n "${SPLUNK_USER:-}" ]]; then
        chown -R "$SPLUNK_USER:$SPLUNK_USER" "$app_path" 2>/dev/null || true
    fi

    print_msg "$GREEN" "App deployed successfully to $app_path"
    log_message "INFO" "Deployment completed successfully"
}

# Function to validate configuration syntax
validate_conf_syntax() {
    local conf_file=$1

    # Basic validation - check for common syntax errors
    if grep -E '^\s*\[.*\[' "$conf_file" > /dev/null; then
        return 1  # Nested brackets
    fi

    if grep -E '=\s*$' "$conf_file" > /dev/null; then
        return 1  # Empty value
    fi

    return 0
}

# Function to validate CSV format
validate_csv() {
    local csv_file=$1

    # Check if file has headers
    if [[ $(head -n 1 "$csv_file" | grep -c ',') -eq 0 ]]; then
        return 1
    fi

    # Check for consistent column count
    local header_cols
    header_cols=$(head -n 1 "$csv_file" | awk -F',' '{print NF}')

    if ! awk -F',' -v cols="$header_cols" 'NF != cols {exit 1}' "$csv_file"; then
        return 1
    fi

    return 0
}

# Function to create secure app.conf
create_secure_app_conf() {
    local app_path=$1

    cat > "$app_path/default/app.conf" <<EOF
[install]
is_configured = 1
state = enabled
build = $(date +%Y%m%d)

[ui]
is_visible = true
label = Security Alerts
description = Comprehensive security monitoring and threat detection for Splunk

[launcher]
author = Security Operations Team
description = Production-ready security alerting framework with hardened configuration
version = 2.0.0

[package]
id = ${APP_NAME}
check_for_updates = false

[triggers]
reload.inputs = simple
reload.props = simple
reload.transforms = simple
reload.savedsearches = simple
EOF

    chmod 644 "$app_path/default/app.conf"
}

# Function to create secure metadata
create_secure_metadata() {
    local app_path=$1

    cat > "$app_path/metadata/default.meta" <<EOF
[]
# Restrict write access to admin and power users only
access = read : [ * ], write : [ admin, power ]
export = system

[savedsearches]
# Critical searches - admin only
access = read : [ admin, power ], write : [ admin ]
export = none

[macros]
# Security macros - restricted access
access = read : [ admin, power ], write : [ admin ]
export = system

[lookups]
# Lookup files - restricted write access
access = read : [ * ], write : [ admin ]
export = system

[transforms]
# Transforms - admin only
access = read : [ admin, power ], write : [ admin ]
export = system

[props]
# Props - admin only
access = read : [ admin, power ], write : [ admin ]
export = system
EOF

    chmod 644 "$app_path/metadata/default.meta"
}

# Function to restart Splunk
restart_splunk() {
    if [[ "$RESTART_SPLUNK" == "yes" ]]; then
        print_msg "$YELLOW" "Restarting Splunk..."

        # Check if Splunk is running
        if "$SPLUNK_HOME/bin/splunk" status 2>/dev/null | grep -q "splunkd is running"; then
            # Perform rolling restart for minimal disruption
            if "$SPLUNK_HOME/bin/splunk" rolling-restart 2>/dev/null; then
                print_msg "$GREEN" "Splunk restarted successfully (rolling restart)"
            else
                # Fallback to regular restart
                "$SPLUNK_HOME/bin/splunk" restart
                print_msg "$GREEN" "Splunk restarted successfully"
            fi
        else
            print_msg "$YELLOW" "Splunk is not running, starting..."
            "$SPLUNK_HOME/bin/splunk" start
        fi

        log_message "INFO" "Splunk service restarted"
    else
        print_msg "$YELLOW" "Please restart Splunk manually to apply changes."
    fi
}

# Function to verify deployment
verify_deployment() {
    print_msg "$YELLOW" "Verifying deployment..."

    # Read credentials if not provided
    if [[ -z "${SPLUNK_AUTH:-}" ]] && [[ "$SECURE_MODE" == "yes" ]]; then
        read_credentials
    fi

    # Check if app is installed
    if [[ -n "${SPLUNK_AUTH:-}" ]]; then
        local app_check
        app_check=$("$SPLUNK_HOME/bin/splunk" list app -auth "$SPLUNK_AUTH" 2>/dev/null | grep -c "$APP_NAME" || true)

        if [[ $app_check -gt 0 ]]; then
            print_msg "$GREEN" "App verified successfully!"
            log_message "INFO" "Deployment verification successful"

            # Run app health check
            run_health_check
        else
            print_msg "$YELLOW" "App deployed but not yet loaded. Please check Splunk."
            log_message "WARN" "App not found in Splunk app list"
        fi
    else
        print_msg "$YELLOW" "Skipping verification (no credentials provided)"
    fi
}

# Function to run health check
run_health_check() {
    print_msg "$YELLOW" "Running health check..."

    local health_checks_passed=0
    local health_checks_total=0

    # Check 1: Verify configuration files
    ((health_checks_total++))
    if [[ -f "$SPLUNK_HOME/etc/apps/$APP_NAME/default/savedsearches.conf" ]]; then
        print_msg "$GREEN" "  ✓ Saved searches configuration found"
        ((health_checks_passed++))
    else
        print_msg "$RED" "  ✗ Saved searches configuration missing"
    fi

    # Check 2: Verify lookups
    ((health_checks_total++))
    if [[ -d "$SPLUNK_HOME/etc/apps/$APP_NAME/lookups" ]] && [[ $(find "$SPLUNK_HOME/etc/apps/$APP_NAME/lookups" -name "*.csv" | wc -l) -gt 0 ]]; then
        print_msg "$GREEN" "  ✓ Lookup files found"
        ((health_checks_passed++))
    else
        print_msg "$RED" "  ✗ Lookup files missing"
    fi

    # Check 3: Verify permissions
    ((health_checks_total++))
    local app_perms
    app_perms=$(stat -c "%a" "$SPLUNK_HOME/etc/apps/$APP_NAME" 2>/dev/null || stat -f "%OLp" "$SPLUNK_HOME/etc/apps/$APP_NAME" 2>/dev/null)
    if [[ "$app_perms" == "755" ]]; then
        print_msg "$GREEN" "  ✓ Correct permissions set"
        ((health_checks_passed++))
    else
        print_msg "$YELLOW" "  ⚠ Permissions: $app_perms (expected: 755)"
    fi

    # Check 4: Verify no sensitive data in logs
    ((health_checks_total++))
    if ! grep -i "password\|secret\|token\|key" "$LOG_FILE" > /dev/null 2>&1; then
        print_msg "$GREEN" "  ✓ No sensitive data in logs"
        ((health_checks_passed++))
    else
        print_msg "$YELLOW" "  ⚠ Potential sensitive data in logs"
    fi

    print_msg "$BLUE" "Health check: $health_checks_passed/$health_checks_total passed"
    log_message "INFO" "Health check completed: $health_checks_passed/$health_checks_total passed"
}

# Function to generate deployment report
generate_report() {
    local report_file="${APP_ROOT}/deployment_report_${TIMESTAMP}.txt"

    {
        echo "====================================="
        echo "Splunk Security Alerts Deployment Report"
        echo "====================================="
        echo "Date: $(date)"
        echo "Deployed by: $(whoami)"
        echo "Splunk Home: $SPLUNK_HOME"
        echo "App Name: $APP_NAME"
        echo "Version: 2.0.0"
        echo ""
        echo "Security Checks:"
        echo "- File integrity: ${VERIFY_CHECKSUMS}"
        echo "- Secure mode: ${SECURE_MODE}"
        echo "- Backup created: ${BACKUP_ENABLED}"
        echo ""
        echo "Files Deployed:"
        find "$SPLUNK_HOME/etc/apps/$APP_NAME" -type f | wc -l
        echo ""
        echo "Configuration Files:"
        find "$SPLUNK_HOME/etc/apps/$APP_NAME" -name "*.conf" -exec basename {} \;
        echo ""
        echo "Lookup Files:"
        find "$SPLUNK_HOME/etc/apps/$APP_NAME/lookups" -name "*.csv" -exec basename {} \;
        echo ""
        echo "====================================="
    } > "$report_file"

    chmod 600 "$report_file"
    print_msg "$GREEN" "Deployment report saved to: $report_file"
}

# Function to display usage
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Secure deployment script for Splunk Security Alerts app

OPTIONS:
    --splunk-home PATH      Path to Splunk installation (default: /opt/splunk)
    --app-name NAME         Name for the app (default: security_alerts)
    --no-restart            Don't restart Splunk after deployment
    --no-backup             Skip backup of existing app
    --no-checksums          Skip file integrity verification
    --insecure              Disable secure mode (not recommended)
    --help                  Show this help message

SECURITY FEATURES:
    - File integrity verification using SHA-256 checksums
    - Secure credential handling (no hardcoded passwords)
    - Restrictive file permissions
    - Comprehensive audit logging
    - Automatic backup with retention policy
    - Input validation and sanitization

EXAMPLES:
    # Standard secure deployment
    $0

    # Custom Splunk location
    $0 --splunk-home /Applications/Splunk

    # Deploy without restart
    $0 --no-restart

ENVIRONMENT VARIABLES:
    SPLUNK_HOME             Splunk installation directory
    SPLUNK_USER             Splunk service user
    SPLUNK_AUTH             Authentication credentials (username:password)

EOF
}

# Main execution
main() {
    print_msg "$GREEN" "====================================="
    print_msg "$GREEN" "Splunk Security Alerts - Secure Deployment"
    print_msg "$GREEN" "====================================="

    # Create log file with secure permissions
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"

    log_message "INFO" "Deployment started by $(whoami)"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --splunk-home)
                SPLUNK_HOME="$2"
                shift 2
                ;;
            --app-name)
                APP_NAME="$2"
                shift 2
                ;;
            --no-restart)
                RESTART_SPLUNK="no"
                shift
                ;;
            --no-backup)
                BACKUP_ENABLED="no"
                shift
                ;;
            --no-checksums)
                VERIFY_CHECKSUMS="no"
                shift
                ;;
            --insecure)
                SECURE_MODE="no"
                print_msg "$YELLOW" "WARNING: Running in insecure mode!"
                log_message "WARN" "Insecure mode enabled"
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                print_msg "$RED" "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Execute deployment steps
    validate_security
    check_prerequisites
    backup_existing
    deploy_app
    restart_splunk
    verify_deployment
    generate_report

    print_msg "$GREEN" "====================================="
    print_msg "$GREEN" "Deployment completed successfully!"
    print_msg "$GREEN" "====================================="
    print_msg "$YELLOW" "Next steps:"
    print_msg "$YELLOW" "1. Review the deployment report"
    print_msg "$YELLOW" "2. Verify app functionality in Splunk Web"
    print_msg "$YELLOW" "3. Update lookup tables with your environment data"
    print_msg "$YELLOW" "4. Configure data inputs as needed"
    print_msg "$YELLOW" "5. Enable and test alerts"
    print_msg "$YELLOW" "6. Review the SECURITY.md file for hardening recommendations"

    log_message "INFO" "Deployment completed successfully"

    # Clean up sensitive environment variables
    unset SPLUNK_AUTH
}

# Run main function
main "$@"