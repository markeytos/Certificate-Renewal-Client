#!/bin/bash

# Environment variables
# KEYCHAIN_PASSWORD
# MAC_CERT_PASSWORD
# MAC_CERT_BASE64
# APPLE_ID
# TEAM_ID
# NOTARIZE_PASSWORD

set -euo pipefail

KEYCHAIN_NAME="build.keychain"

echo "[INFO] Creating and configuring keychain"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_NAME"
security default-keychain -s "$KEYCHAIN_NAME"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_NAME"

echo "[INFO] Creating certificate in proper format (p12)"
echo "$MAC_CERT_BASE64" | base64 --decode >cert.p12

echo "[INFO] Importing certificate into keychain"
security import cert.p12 -k "$KEYCHAIN_NAME" -P "$MAC_CERT_PASSWORD" -T /usr/bin/codesign

security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_NAME"

rm cert.p12
