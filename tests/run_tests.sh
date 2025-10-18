#!/bin/bash

# Test runner for Splunk Security Alerts

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}Splunk Security Alerts - Test Suite${NC}"
echo -e "${GREEN}======================================${NC}"

# Change to tests directory
cd "$(dirname "$0")"

# Test 1: Validate configuration files exist
echo -e "\n${YELLOW}Test 1: Checking configuration files...${NC}"
required_files=(
    "../default/savedsearches.conf"
    "../default/props.conf"
    "../default/transforms.conf"
    "../default/macros.conf"
)

for file in "${required_files[@]}"; do
    if [[ -f "$file" ]]; then
        echo -e "  ${GREEN}✓${NC} $file exists"
    else
        echo -e "  ${RED}✗${NC} $file missing"
        exit 1
    fi
done

# Test 2: Validate lookup files
echo -e "\n${YELLOW}Test 2: Checking lookup files...${NC}"
lookup_files=(
    "../lookups/authorized_ips.csv"
    "../lookups/malicious_ips.csv"
    "../lookups/sensitive_hosts.csv"
    "../lookups/authorized_users.csv"
    "../lookups/critical_files.csv"
)

for file in "${lookup_files[@]}"; do
    if [[ -f "$file" ]]; then
        echo -e "  ${GREEN}✓${NC} $file exists"
        # Check CSV format
        if head -n 1 "$file" | grep -q ","; then
            echo -e "    ${GREEN}✓${NC} Valid CSV format"
        else
            echo -e "    ${RED}✗${NC} Invalid CSV format"
        fi
    else
        echo -e "  ${RED}✗${NC} $file missing"
    fi
done

# Test 3: Validate dashboards
echo -e "\n${YELLOW}Test 3: Checking dashboards...${NC}"
dashboard_files=(
    "../dashboards/security_operations_dashboard.xml"
    "../dashboards/ssh_monitoring_dashboard.xml"
)

for file in "${dashboard_files[@]}"; do
    if [[ -f "$file" ]]; then
        echo -e "  ${GREEN}✓${NC} $file exists"
        # Check for valid XML
        if xmllint --noout "$file" 2>/dev/null; then
            echo -e "    ${GREEN}✓${NC} Valid XML format"
        else
            echo -e "    ${YELLOW}⚠${NC} XML validation not available or failed"
        fi
    else
        echo -e "  ${RED}✗${NC} $file missing"
    fi
done

# Test 4: Run Python tests if available
echo -e "\n${YELLOW}Test 4: Running Python validation tests...${NC}"
if command -v python3 &> /dev/null; then
    python3 test_searches.py
else
    echo -e "  ${YELLOW}⚠${NC} Python3 not found, skipping validation tests"
fi

# Test 5: Check for required directories
echo -e "\n${YELLOW}Test 5: Checking directory structure...${NC}"
required_dirs=(
    "../default"
    "../lookups"
    "../dashboards"
    "../scripts"
    "../documentation"
)

for dir in "${required_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
        echo -e "  ${GREEN}✓${NC} $dir exists"
    else
        echo -e "  ${RED}✗${NC} $dir missing"
    fi
done

# Test 6: Validate deployment script
echo -e "\n${YELLOW}Test 6: Checking deployment script...${NC}"
if [[ -f "../scripts/deploy.sh" ]]; then
    echo -e "  ${GREEN}✓${NC} Deploy script exists"
    if [[ -x "../scripts/deploy.sh" ]]; then
        echo -e "  ${GREEN}✓${NC} Deploy script is executable"
    else
        echo -e "  ${YELLOW}⚠${NC} Deploy script is not executable"
    fi
else
    echo -e "  ${RED}✗${NC} Deploy script missing"
fi

# Test 7: Check README
echo -e "\n${YELLOW}Test 7: Checking documentation...${NC}"
if [[ -f "../README.md" ]]; then
    echo -e "  ${GREEN}✓${NC} README.md exists"
    line_count=$(wc -l < "../README.md")
    if [[ $line_count -gt 50 ]]; then
        echo -e "  ${GREEN}✓${NC} README appears comprehensive ($line_count lines)"
    else
        echo -e "  ${YELLOW}⚠${NC} README might be incomplete ($line_count lines)"
    fi
else
    echo -e "  ${RED}✗${NC} README.md missing"
fi

echo -e "\n${GREEN}======================================${NC}"
echo -e "${GREEN}Test suite completed!${NC}"
echo -e "${GREEN}======================================${NC}"