#!/bin/bash
# Santamon installation script for macOS

set -e

echo "Installing Santamon..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

# Check if santamon binary exists
if [ ! -f "./santamon" ]; then
  echo "Error: santamon binary not found in current directory"
  echo "Please build with: go build -o santamon ./cmd/santamon"
  exit 1
fi

# Create directories
echo "Creating directories..."
mkdir -p /etc/santamon
mkdir -p /var/lib/santamon
mkdir -p /var/log

# Install binary
echo "Installing binary..."
cp santamon /usr/local/bin/santamon
chmod 755 /usr/local/bin/santamon

# Install configuration files
echo "Installing configuration..."
if [ ! -f /etc/santamon/config.yaml ]; then
  cp configs/santamon.yaml /etc/santamon/config.yaml
  chmod 600 /etc/santamon/config.yaml
else
  echo "Config file already exists, skipping..."
fi

if [ ! -f /etc/santamon/rules.yaml ]; then
  cp configs/rules.yaml /etc/santamon/rules.yaml
  chmod 600 /etc/santamon/rules.yaml
else
  echo "Rules file already exists, skipping..."
fi

# Set proper permissions
echo "Setting permissions..."
chown -R root:wheel /etc/santamon
chown -R root:wheel /var/lib/santamon
chmod 700 /var/lib/santamon

# Install LaunchDaemon
echo "Installing LaunchDaemon..."
cp scripts/com.santamon.plist /Library/LaunchDaemons/com.santamon.plist
chmod 644 /Library/LaunchDaemons/com.santamon.plist
chown root:wheel /Library/LaunchDaemons/com.santamon.plist

echo ""
echo "Installation complete!"
echo ""
echo "IMPORTANT: Before starting, you need to:"
echo "1. Set your API key in /Library/LaunchDaemons/com.santamon.plist"
echo "   Edit the EnvironmentVariables section and add your key"
echo ""
echo "2. Ensure Santa is configured for protobuf logging:"
echo "   sudo santactl config set EventLogType protobuf"
echo ""
echo "3. Start the service:"
echo "   sudo launchctl bootstrap system /Library/LaunchDaemons/com.santamon.plist"
echo ""
echo "Stop the service:"
echo "   sudo launchctl bootout system /Library/LaunchDaemons/com.santamon.plist"
echo ""
echo "Check if running:"
echo "   sudo launchctl list | grep santamon"
echo ""
echo "View logs:"
echo "   tail -f /var/log/santamon.log"
echo ""
echo "Verify status:"
echo "   santamon status"
echo "   santamon db stats"
