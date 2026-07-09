<?php
/**
 * IP-Block.com — Plesk pre-uninstall hook (runs as root before removal).
 * Removes the auto_prepend_file registration and the installed guard so that
 * customer sites stop loading it. Config is left in place.
 */

echo "[ipblock] removing auto_prepend_file INI drop-ins\n";
$patterns = array(
    '/opt/plesk/php/*/etc/php.d/zzz-ipblock.ini',
    '/etc/php/*/fpm/conf.d/zzz-ipblock.ini',
);
foreach ($patterns as $p) {
    foreach (glob($p) as $ini) {
        @unlink($ini);
    }
}

echo "[ipblock] removing guard\n";
@unlink('/opt/ipblock/ipblock-guard.php');
@rmdir('/opt/ipblock');

echo "[ipblock] reloading web server / PHP-FPM\n";
@shell_exec('/usr/local/psa/admin/sbin/httpdmng --reconfigure-all 2>/dev/null');

echo "[ipblock] uninstall hook complete. Config kept under /usr/local/psa/var/modules/ipblock/.\n";
