<?php
/**
 * IP-Block.com — Plesk post-install hook (runs as root after install/upgrade).
 *
 *  - Copies the enforcement guard to /opt/ipblock/ipblock-guard.php
 *  - Creates a default config file if none exists
 *  - Registers the guard as auto_prepend_file for every Plesk PHP handler
 *  - Reloads Plesk PHP-FPM / web server so the change takes effect
 */

$moduleId   = 'ipblock';
$plibRes    = "/usr/local/psa/admin/plib/modules/$moduleId/plib/resources/ipblock-guard.php";
$guardDir   = '/opt/ipblock';
$guardFile  = "$guardDir/ipblock-guard.php";
$varDir     = "/usr/local/psa/var/modules/$moduleId";
$configFile = "$varDir/config.json";

echo "[ipblock] installing enforcement guard\n";
@mkdir($guardDir, 0755, true);
if (is_readable($plibRes)) {
    copy($plibRes, $guardFile);
    @chmod($guardFile, 0644);
} else {
    fwrite(STDERR, "[ipblock] WARNING: guard resource not found at $plibRes\n");
}

echo "[ipblock] preparing config\n";
@mkdir($varDir, 0755, true);
if (!is_file($configFile)) {
    $default = array(
        'enabled'        => false,
        'site_id'        => '',
        'api_key'        => '',
        'api_url'        => 'https://api.ip-block.com/v1/check',
        'fail_open'      => true,
        'cache_ttl'      => 300,
        'behind_proxy'   => false,
        'real_ip_header' => 'X-Forwarded-For',
        'block_action'   => '403',
        'block_message'  => 'Access denied.',
        'redirect_url'   => 'https://www.ip-block.com/blocked.php',
        'whitelist'      => array(),
    );
    file_put_contents($configFile, json_encode($default, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    @chmod($configFile, 0644);
}

echo "[ipblock] registering auto_prepend_file for Plesk PHP handlers\n";
$ini = "; Managed by the IP-Block.com Plesk extension. Do not edit by hand.\n"
     . "auto_prepend_file = $guardFile\n";
$count = 0;
foreach (glob('/opt/plesk/php/*/etc/php.d') as $phpd) {
    if (@file_put_contents("$phpd/zzz-ipblock.ini", $ini) !== false) {
        $count++;
    }
}
// Also cover the OS-vendor PHP that Plesk may expose, if present.
foreach (glob('/etc/php/*/fpm/conf.d') as $phpd) {
    if (@file_put_contents("$phpd/zzz-ipblock.ini", $ini) !== false) {
        $count++;
    }
}
echo "[ipblock] wrote $count auto_prepend INI drop-in(s)\n";

echo "[ipblock] reloading web server / PHP-FPM\n";
@shell_exec('/usr/local/psa/admin/sbin/httpdmng --reconfigure-all 2>/dev/null');
@shell_exec('/usr/local/psa/bin/php_handler --reread 2>/dev/null');

echo "[ipblock] done. Configure it in Plesk > Extensions > IP-Block Protection.\n";
