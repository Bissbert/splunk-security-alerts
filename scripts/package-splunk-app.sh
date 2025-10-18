#!/bin/bash

# Package Splunk Security Alerts App
# Creates a .spl file (Splunk app package) from the security_alerts_app directory

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
APP_DIR="${PROJECT_ROOT}/security_alerts_app"
BUILD_DIR="${PROJECT_ROOT}/build"
DIST_DIR="${PROJECT_ROOT}/dist"

echo -e "${GREEN}=== Splunk App Packager ===${NC}"
echo "Project root: ${PROJECT_ROOT}"

# Validate app directory exists
if [ ! -d "$APP_DIR" ]; then
    echo -e "${RED}Error: App directory not found at ${APP_DIR}${NC}"
    exit 1
fi

# Read version from app.conf if it exists
VERSION="3.0.0"
if [ -f "${APP_DIR}/default/app.conf" ]; then
    VERSION_FROM_CONF=$(grep -E "^version\s*=" "${APP_DIR}/default/app.conf" 2>/dev/null | sed 's/.*=\s*//' | tr -d ' ')
    if [ ! -z "$VERSION_FROM_CONF" ]; then
        VERSION="$VERSION_FROM_CONF"
    fi
fi

# Allow version override from command line
if [ ! -z "$1" ]; then
    VERSION="$1"
fi

echo -e "${YELLOW}Building version: ${VERSION}${NC}"

# Clean and create build directories
echo "Preparing build directories..."
rm -rf "$BUILD_DIR" "$DIST_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR"

# Copy app to build directory
echo "Copying app files..."
cp -r "$APP_DIR" "$BUILD_DIR/security_alerts_app"

# Clean up unwanted files
echo "Cleaning build directory..."
find "$BUILD_DIR" -type f -name "*.pyc" -delete
find "$BUILD_DIR" -type f -name ".DS_Store" -delete
find "$BUILD_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$BUILD_DIR" -type d -name ".git" -exec rm -rf {} + 2>/dev/null || true

# Set proper permissions
echo "Setting file permissions..."
find "$BUILD_DIR/security_alerts_app" -type f -exec chmod 644 {} \;
find "$BUILD_DIR/security_alerts_app" -type d -exec chmod 755 {} \;

# Make scripts executable if they exist
if [ -d "$BUILD_DIR/security_alerts_app/bin" ]; then
    find "$BUILD_DIR/security_alerts_app/bin" -type f \( -name "*.sh" -o -name "*.py" \) -exec chmod 755 {} \;
fi

# Create the .spl package (tar.gz format)
PACKAGE_NAME="security_alerts_app-${VERSION}.spl"
echo "Creating package: ${PACKAGE_NAME}"

cd "$BUILD_DIR"
tar -czf "${DIST_DIR}/${PACKAGE_NAME}" security_alerts_app

# Create SHA256 checksum
echo "Generating checksum..."
cd "$DIST_DIR"
shasum -a 256 "${PACKAGE_NAME}" > "${PACKAGE_NAME}.sha256"

# Display results
echo -e "${GREEN}=== Build Complete ===${NC}"
echo "Package created: ${DIST_DIR}/${PACKAGE_NAME}"
echo "Checksum file: ${DIST_DIR}/${PACKAGE_NAME}.sha256"
echo ""
echo "Package contents:"
tar -tzf "${DIST_DIR}/${PACKAGE_NAME}" | head -20
echo "..."
echo ""
echo "Checksum:"
cat "${DIST_DIR}/${PACKAGE_NAME}.sha256"

# Clean up build directory
rm -rf "$BUILD_DIR"

echo -e "${GREEN}Success! Package ready for deployment.${NC}"