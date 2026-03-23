#!/bin/bash

# Environment variables
# NOTARIZE_PASSWORD
# TEAM_ID
# SIGNING_IDENTITY
# APPLE_ID
# VERSION

BASE_PATH="./DotNetCertAuthSample"
CSPROJ_FILE_PATH="${BASE_PATH}/DotNetCertAuthSample.csproj"

RELEASE_PATH="${BASE_PATH}/bin/Release"
PUBLISH_OUTPUT_DIRECTORY="${RELEASE_PATH}/net10.0/osx-arm64/publish"
BINARY_PATH="${PUBLISH_OUTPUT_DIRECTORY}/EZCACertManager"
ZIP_PATH="${PUBLISH_OUTPUT_DIRECTORY}/EZCACertManager.zip"
FINAL_ZIP_PATH="${BASE_PATH}/EZCACertManager.zip"
ENTITLEMENTS="./EZCACertManager.entitlements"

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
  -p:Version="$VERSION" \
  --self-contained true

echo "[INFO] Signing binary"
codesign --force --timestamp --options=runtime --entitlements "$ENTITLEMENTS" --sign "$SIGNING_IDENTITY" "$BINARY_PATH"

echo "[INFO] Verifying binary..."
codesign --verify --verbose=4 "$BINARY_PATH"
codesign --verify --deep --strict --verbose=2 "$BINARY_PATH"

zip -j "$ZIP_PATH" "$BINARY_PATH"

echo "[INFO] Submitting zip..."

xcrun notarytool submit "$ZIP_PATH" --apple-id "$APPLE_ID" --password "$NOTARIZE_PASSWORD" --team-id "$TEAM_ID" --wait

mv "$ZIP_PATH" "$FINAL_ZIP_PATH"

echo "[INFO] Certificate Renewal Client built and notarized!"
