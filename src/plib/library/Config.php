<?php
/**
 * IP-Block.com — Plesk config helper.
 *
 * Bridges the Plesk settings store (pm_Settings, DB-backed) and the JSON config
 * file that the shared enforcement guard reads at runtime. The guard cannot talk
 * to the Plesk DB, so every save is also mirrored to:
 *
 *     <extension var dir>/config.json
 *     == /usr/local/psa/var/modules/ipblock/config.json
 *
 * which is one of the guard's default config search paths.
 */
class Modules_Ipblock_Config
{
    /** @return array Effective settings merged over defaults. */
    public static function defaults()
    {
        return array(
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
    }

    /** Absolute path to the JSON file the guard consumes. */
    public static function file()
    {
        return pm_Context::getVarDir() . '/config.json';
    }

    /** Load current settings (from JSON file, falling back to defaults). */
    public static function load()
    {
        $cfg = self::defaults();
        $file = self::file();
        if (is_readable($file)) {
            $data = json_decode((string) file_get_contents($file), true);
            if (is_array($data)) {
                $cfg = array_merge($cfg, $data);
            }
        }
        if (!is_array($cfg['whitelist'])) {
            $cfg['whitelist'] = array();
        }
        return $cfg;
    }

    /**
     * Persist settings to both pm_Settings and the JSON file.
     *
     * @param array $values Raw form values.
     */
    public static function save(array $values)
    {
        $cfg = self::defaults();

        $cfg['enabled']        = !empty($values['enabled']);
        $cfg['site_id']        = trim((string) ($values['site_id'] ?? ''));
        $cfg['api_key']        = trim((string) ($values['api_key'] ?? ''));
        $cfg['api_url']        = trim((string) ($values['api_url'] ?? '')) ?: $cfg['api_url'];
        $cfg['fail_open']      = !empty($values['fail_open']);
        $cfg['cache_ttl']      = max(0, (int) ($values['cache_ttl'] ?? 300));
        $cfg['behind_proxy']   = !empty($values['behind_proxy']);
        $cfg['real_ip_header'] = trim((string) ($values['real_ip_header'] ?? 'X-Forwarded-For')) ?: 'X-Forwarded-For';
        $cfg['block_action']   = (($values['block_action'] ?? '403') === 'redirect') ? 'redirect' : '403';
        $cfg['block_message']  = trim((string) ($values['block_message'] ?? 'Access denied.'));
        $cfg['redirect_url']   = trim((string) ($values['redirect_url'] ?? '')) ?: $cfg['redirect_url'];

        $wl = array();
        foreach (preg_split('/[\r\n,]+/', (string) ($values['whitelist'] ?? '')) as $line) {
            $line = trim($line);
            if ($line !== '') {
                $wl[] = $line;
            }
        }
        $cfg['whitelist'] = $wl;

        // Mirror scalar values into pm_Settings (handy for other components).
        foreach ($cfg as $k => $v) {
            if (is_scalar($v) || is_bool($v)) {
                pm_Settings::set($k, is_bool($v) ? ($v ? '1' : '0') : (string) $v);
            }
        }
        pm_Settings::set('whitelist', implode("\n", $cfg['whitelist']));

        self::writeFile($cfg);
        return $cfg;
    }

    /** Write the JSON config file the guard reads (0644, world-readable). */
    public static function writeFile(array $cfg)
    {
        $dir = pm_Context::getVarDir();
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        $json = json_encode($cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $file = self::file();
        file_put_contents($file, $json, LOCK_EX);
        @chmod($file, 0644);
        return $file;
    }
}
