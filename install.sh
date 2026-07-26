#!/bin/bash
# Install script for Cockpit IP Unblock Plugin
# Run with: sudo bash install.sh

set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PLUGIN_DIR="/usr/share/cockpit/ip-unblock"
HELPER="/usr/local/bin/cockpit-ip-unblock-helper"
STATE_DIR="/var/lib/cockpit"
LOGROTATE_FILE="/etc/logrotate.d/cockpit-ip-unblock"
CONFIG_FILE="/etc/cockpit-ip-unblock.conf"

echo "=== Installing Cockpit IP Unblock Plugin ==="

# 1. Create plugin directory
echo "[1/5] Installing plugin files to ${PLUGIN_DIR} ..."
mkdir -p "${PLUGIN_DIR}"
cp "${SCRIPT_DIR}/usr-share-cockpit-ip-unblock/"* "${PLUGIN_DIR}/"

# 2. Install backend helper
echo "[2/5] Installing backend helper to ${HELPER} ..."
cp "${SCRIPT_DIR}/usr-local-bin/cockpit-ip-unblock-helper" "${HELPER}"
chmod 755 "${HELPER}"

# 3. Create state directory
echo "[3/5] Creating state directory ${STATE_DIR} ..."
mkdir -p "${STATE_DIR}"
chmod 755 "${STATE_DIR}"

if [ ! -e "${CONFIG_FILE}" ]; then
    cp "${SCRIPT_DIR}/cockpit-ip-unblock.conf" "${CONFIG_FILE}"
    chmod 640 "${CONFIG_FILE}"
fi

# 4. Install logrotate config
echo "[4/5] Installing logrotate config ..."
cp "${SCRIPT_DIR}/cockpit-ip-unblock.logrotate" "${LOGROTATE_FILE}"
chmod 644 "${LOGROTATE_FILE}"

# 5. Install sudoers rule (allow all users to run helper without password)
echo "[5/6] Installing sudoers rule ..."
cp "${SCRIPT_DIR}/cockpit-ip-unblock.sudoers" /etc/sudoers.d/cockpit-ip-unblock
chmod 440 /etc/sudoers.d/cockpit-ip-unblock

# 6. Ensure iptables is available
echo "[6/6] Checking iptables ..."
if ! command -v iptables >/dev/null 2>&1; then
    echo "WARNING: iptables not found. Install iptables for the plugin to work."
fi

echo ""
echo "=== Installation complete ==="
echo ""
echo "Plugin files:"
echo "  ${PLUGIN_DIR}/manifest.json"
echo "  ${PLUGIN_DIR}/index.html"
echo "  ${PLUGIN_DIR}/ip-unblock.js"
echo "  ${PLUGIN_DIR}/ip-unblock.css"
echo ""
echo "Backend helper: ${HELPER}"
echo "State file: ${STATE_DIR}/ip-unblock-state.json"
echo "Audit log: /var/log/cockpit-ip-unblock.log"
echo ""
echo "Reload Cockpit to load the plugin:"
echo "  sudo systemctl restart cockpit.socket"
echo ""
echo "Access at: https://<server>:9090/ip-unblock"
