#!/bin/bash

# Splunk Security Alerts Deployment Script
# Deploys the security alerting app to a Splunk instance

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
SPLUNK_HOME="/opt/splunk"
APP_NAME="security_alerts"
RESTART_SPLUNK="yes"

# Function to print colored output
print_msg() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check prerequisites
check_prerequisites() {
    print_msg "$YELLOW" "Checking prerequisites..."

    # Check if running as appropriate user
    if [[ $EUID -eq 0 ]]; then
        print_msg "$RED" "This script should not be run as root!"
        exit 1
    fi

    # Check if Splunk home exists
    if [[ ! -d "$SPLUNK_HOME" ]]; then
        print_msg "$RED" "Splunk home directory not found at $SPLUNK_HOME"
        read -p "Enter your Splunk home directory: " SPLUNK_HOME
        if [[ ! -d "$SPLUNK_HOME" ]]; then
            print_msg "$RED" "Invalid Splunk home directory!"
            exit 1
        fi
    fi

    print_msg "$GREEN" "Prerequisites check passed!"
}

# Function to backup existing app
backup_existing() {
    local app_path="$SPLUNK_HOME/etc/apps/$APP_NAME"
    if [[ -d "$app_path" ]]; then
        print_msg "$YELLOW" "Backing up existing app..."
        local backup_name="${APP_NAME}_backup_$(date +%Y%m%d_%H%M%S)"
        mv "$app_path" "$SPLUNK_HOME/etc/apps/$backup_name"
        print_msg "$GREEN" "Existing app backed up to $backup_name"
    fi
}

# Function to deploy the app
deploy_app() {
    print_msg "$YELLOW" "Deploying security alerts app..."

    local app_path="$SPLUNK_HOME/etc/apps/$APP_NAME"

    # Create app directory structure
    mkdir -p "$app_path"/{default,local,lookups,metadata}

    # Copy configuration files from the new app structure
    cp -r security_alerts_app/default/* "$app_path/default/" 2>/dev/null || true
    cp -r security_alerts_app/lookups/* "$app_path/lookups/" 2>/dev/null || true
    cp -r security_alerts_app/bin/* "$app_path/bin/" 2>/dev/null || true
    cp -r security_alerts_app/metadata/* "$app_path/metadata/" 2>/dev/null || true

    # Dashboards are already in the correct location in security_alerts_app
    if [[ -d "security_alerts_app/default/data/ui/views" ]]; then
        mkdir -p "$app_path/default/data/ui/views"
        cp security_alerts_app/default/data/ui/views/*.xml "$app_path/default/data/ui/views/"
    fi

    # Create app.conf
    cat > "$app_path/default/app.conf" <<EOF
[install]
is_configured = 1
state = enabled
build = 1

[ui]
is_visible = true
label = Security Alerts
description = Comprehensive security monitoring and threat detection for Splunk

[launcher]
author = Security Operations Team
description = Production-ready security alerting framework for detecting threats and incidents
version = 1.0.0

[package]
id = security_alerts
check_for_updates = false
EOF

    # Create metadata
    cat > "$app_path/metadata/default.meta" <<EOF
[]
access = read : [ * ], write : [ admin, power ]
export = system
EOF

    # Set proper permissions
    chmod -R 755 "$app_path"
    chmod 644 "$app_path"/lookups/*.csv 2>/dev/null || true

    print_msg "$GREEN" "App deployed successfully to $app_path"
}

# Function to restart Splunk
restart_splunk() {
    if [[ "$RESTART_SPLUNK" == "yes" ]]; then
        print_msg "$YELLOW" "Restarting Splunk..."
        "$SPLUNK_HOME/bin/splunk" restart
        print_msg "$GREEN" "Splunk restarted successfully!"
    else
        print_msg "$YELLOW" "Please restart Splunk manually to apply changes."
    fi
}

# Function to verify deployment
verify_deployment() {
    print_msg "$YELLOW" "Verifying deployment..."

    # Check if app is installed
    local app_check=$("$SPLUNK_HOME/bin/splunk" list app -auth admin:changeme 2>/dev/null | grep -c "$APP_NAME" || true)

    if [[ $app_check -gt 0 ]]; then
        print_msg "$GREEN" "App verified successfully!"
    else
        print_msg "$YELLOW" "App deployed but not yet loaded. Please restart Splunk."
    fi
}

# Main execution
main() {
    print_msg "$GREEN" "==================================="
    print_msg "$GREEN" "Splunk Security Alerts Deployment"
    print_msg "$GREEN" "==================================="

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
            --help)
                echo "Usage: $0 [options]"
                echo "Options:"
                echo "  --splunk-home PATH    Path to Splunk installation (default: /opt/splunk)"
                echo "  --app-name NAME       Name for the app (default: security_alerts)"
                echo "  --no-restart          Don't restart Splunk after deployment"
                echo "  --help                Show this help message"
                exit 0
                ;;
            *)
                print_msg "$RED" "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    check_prerequisites
    backup_existing
    deploy_app
    restart_splunk
    verify_deployment

    print_msg "$GREEN" "==================================="
    print_msg "$GREEN" "Deployment completed successfully!"
    print_msg "$GREEN" "==================================="
    print_msg "$YELLOW" "Next steps:"
    print_msg "$YELLOW" "1. Log into Splunk Web"
    print_msg "$YELLOW" "2. Navigate to Apps > Security Alerts"
    print_msg "$YELLOW" "3. Update lookup tables with your environment data"
    print_msg "$YELLOW" "4. Configure data inputs if needed"
    print_msg "$YELLOW" "5. Review and enable alerts"
}

# Run main function
main "$@"