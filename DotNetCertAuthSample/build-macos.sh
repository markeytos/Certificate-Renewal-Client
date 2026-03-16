#!/bin/bash

# Environment variables
# NOTARIZE_PASSWORD
# TEAM_ID
# SIGNING_IDENTITY
# APPLE_ID
# ENTITLEMENTS

BASE_PATH="./DotNetCertAuthSample"
CSPROJ_FILE_PATH="${BASE_PATH}/DotNetCertAuthSample.csproj"

RELEASE_PATH="${BASE_PATH}/bin/Release"
PUBLISH_OUTPUT_DIRECTORY="${RELEASE_PATH}/net10.0/osx-arm64/publish/"
BINARY_PATH="${PUBLISH_OUTPUT_DIRECTORY}/EZCACertManager"

set -eou pipefail

# Build and publish the macOS app
echo "[INFO] Building macOS app..."

dotnet publish "$CSPROJ_FILE_PATH" \
  --framework net10.0 \
  -r osx-arm64 \
  --configuration Release \
  -p:UseAppHost=true \
  -p:PublishReadyToRun=true \
  -p:PublishSingleFile=true \
  --self-contained true

echo "[INFO] Signing binary"
codesign --force --timestamp --options=runtime --entitlements "$ENTITLEMENTS" --sign "$SIGNING_IDENTITY" "$BINARY_PATH"

echo "[INFO] Verifying binary..."
codesign --verify --verbose=4 "$BINARY_PATH"
codesign --verify --deep --strict --verbose=2 "$BINARY_PATH"

echo "[INFO] Submitting and stapling binary..."

xcrun notarytool submit "$BINARY_PATH" --apple-id "$APPLE_ID" --password "$NOTARIZE_PASSWORD" --team-id "$TEAM_ID" --wait
xcrun stapler staple "$BINARY_PATH"
xcrun stapler validate "$BINARY_PATH"

echo "[INFO] Verifying App with GateKeeper..."

# check Gatekeeper
spctl -a -vvv --assess --type execute "$BINARY_PATH"
spctl -a -vvv "$BINARY_PATH"

echo "[INFO] Certificate Renewal Client Installed!"
