<?php
/**
 * =============================================================================
 *  IP-Block.com — Shared Enforcement Guard (PHP auto_prepend_file)
 * =============================================================================
 *
 *  ONE guard, reused across every hosting-control-panel integration
 *  (cPanel/WHM, Plesk, DirectAdmin). It is loaded automatically for every
 *  customer PHP request via the `auto_prepend_file` INI directive, checks the
 *  visitor against the IP-Block.com API and, if the API says so, blocks the
 *  request BEFORE the customer's application code runs.
 *
 *  Design goals:
 *    - Zero configuration in customer code. The panel's admin UI writes a JSON
 *      config file; this guard reads it.
 *    - Never break a site. Any error, timeout, malformed response or missing
 *      config results in FAIL-OPEN (request is allowed) unless the admin has
 *      explicitly set fail_open=false.
 *    - Only screen normal, interactive web requests. CLI, cron and WP-CLI style
 *      invocations are always allowed through untouched.
 *    - Cheap. Per-IP decisions are cached (APCu when available, otherwise a
 *      temp file) for `cache_ttl` seconds so we do not hit the API on every
 *      request from the same visitor.
 *
 *  API CONTRACT (fixed):
 *    POST {api_url}                (default https://api.ip-block.com/v1/check)
 *    Header: Content-Type: application/json
 *    Body:   {"api_key","site_id","ip","user_agent","referrer"}   (key in BODY)
 *    Reply:  {"action":"allow"} | {"action":"block"}
 *    Blocked ONLY when action === "block". Timeout 1 second.
 *
 *  This file is intentionally dependency-free and safe to include more than
 *  once. It must never emit warnings/notices into customer output.
 * =============================================================================
 */

// -----------------------------------------------------------------------------
// Re-entry / self-protection guard.
// auto_prepend_file can, in odd stacks, be evaluated more than once. Make sure
// we only ever run the check a single time per request and never fatal on a
// double-include.
// -----------------------------------------------------------------------------
if (defined('IPBLOCK_GUARD_LOADED')) {
    return;
}
define('IPBLOCK_GUARD_LOADED', true);

if (!function_exists('ipblock_guard_run')) {

    /**
     * Locate the JSON config file written by the panel's admin UI.
     * The first readable candidate wins. Panels may also export the
     * IPBLOCK_CONFIG environment variable or define IPBLOCK_CONFIG_FILE.
     *
     * @return string|null Absolute path to a readable config file, or null.
     */
    function ipblock_guard_config_path()
    {
        $candidates = array();

        // Explicit overrides (highest priority).
        $env = getenv('IPBLOCK_CONFIG');
        if ($env) {
            $candidates[] = $env;
        }
        if (defined('IPBLOCK_CONFIG_FILE')) {
            $candidates[] = IPBLOCK_CONFIG_FILE;
        }

        // Panel default locations.
        $candidates[] = '/etc/ipblock/config.json';                        // cPanel/WHM + generic
        $candidates[] = '/usr/local/psa/var/modules/ipblock/config.json';  // Plesk
        $candidates[] = '/usr/local/directadmin/plugins/ipblock/config.json'; // DirectAdmin

        foreach ($candidates as $path) {
            if ($path && @is_readable($path)) {
                return $path;
            }
        }
        return null;
    }

    /**
     * Load and normalise configuration. Returns an array of effective settings
     * merged over safe defaults. Returns null only when protection should be
     * skipped entirely (no/invalid config, or disabled).
     *
     * @return array|null
     */
    function ipblock_guard_config()
    {
        $defaults = array(
            'enabled'      => true,
            'site_id'      => '',
            'api_key'      => '',
            'api_url'      => 'https://api.ip-block.com/v1/check',
            'fail_open'    => true,     // allow on any error/timeout
            'cache_ttl'    => 300,      // seconds to cache a per-IP decision
            'behind_proxy' => false,    // trust X-Forwarded-For / real-IP header
            'real_ip_header' => 'X-Forwarded-For',
            'block_action' => '403',    // '403' | 'redirect'
            'block_message' => 'Access denied.',
            'redirect_url' => 'https://www.ip-block.com/blocked.php',
            'whitelist'    => array(),  // IPs / CIDR ranges never checked
        );

        $path = ipblock_guard_config_path();
        if ($path === null) {
            return null; // no config yet -> do nothing (fail open)
        }

        $raw = @file_get_contents($path);
        if ($raw === false || $raw === '') {
            return null;
        }

        $cfg = json_decode($raw, true);
        if (!is_array($cfg)) {
            return null; // malformed config -> fail open
        }

        $cfg = array_merge($defaults, $cfg);

        // Coerce types defensively (config may be edited by hand).
        $cfg['enabled']      = ipblock_guard_bool($cfg['enabled']);
        $cfg['fail_open']    = ipblock_guard_bool($cfg['fail_open']);
        $cfg['behind_proxy'] = ipblock_guard_bool($cfg['behind_proxy']);
        $cfg['cache_ttl']    = (int) $cfg['cache_ttl'];
        if ($cfg['cache_ttl'] < 0) {
            $cfg['cache_ttl'] = 0;
        }
        if (!is_array($cfg['whitelist'])) {
            $cfg['whitelist'] = array();
        }
        $cfg['block_action'] = ($cfg['block_action'] === 'redirect') ? 'redirect' : '403';

        // Disabled or missing credentials -> nothing to enforce.
        if (!$cfg['enabled'] || $cfg['site_id'] === '' || $cfg['api_key'] === '') {
            return null;
        }

        return $cfg;
    }

    /**
     * Loose boolean parser ("1", "true", "yes", "on" => true).
     */
    function ipblock_guard_bool($v)
    {
        if (is_bool($v)) {
            return $v;
        }
        if (is_int($v)) {
            return $v !== 0;
        }
        $v = strtolower(trim((string) $v));
        return in_array($v, array('1', 'true', 'yes', 'on'), true);
    }

    /**
     * Determine whether this is a request we should even look at. We ONLY screen
     * ordinary web requests. CLI, cron, WP-CLI and any SAPI without a remote
     * address are always let through so we never break background jobs.
     *
     * @return bool
     */
    function ipblock_guard_is_web_request()
    {
        $sapi = php_sapi_name();
        if ($sapi === 'cli' || $sapi === 'phpdbg') {
            return false;
        }
        if (defined('WP_CLI') && WP_CLI) {
            return false;
        }
        // No client address means this is not a browser-facing request.
        if (empty($_SERVER['REMOTE_ADDR'])) {
            return false;
        }
        return true;
    }

    /**
     * Resolve the real client IP, honouring the panel's behind_proxy setting.
     * When behind a trusted reverse proxy / CDN, take the left-most public
     * address from the configured real-IP header; otherwise use REMOTE_ADDR.
     *
     * @param array $cfg
     * @return string
     */
    function ipblock_guard_client_ip($cfg)
    {
        $remote = isset($_SERVER['REMOTE_ADDR']) ? trim($_SERVER['REMOTE_ADDR']) : '';

        if (!empty($cfg['behind_proxy'])) {
            // Normalise header name -> $_SERVER key (e.g. X-Forwarded-For -> HTTP_X_FORWARDED_FOR)
            $key = 'HTTP_' . strtoupper(str_replace('-', '_', $cfg['real_ip_header']));
            if (!empty($_SERVER[$key])) {
                // XFF may be a comma-separated list: client, proxy1, proxy2...
                $parts = explode(',', $_SERVER[$key]);
                foreach ($parts as $candidate) {
                    $candidate = trim($candidate);
                    if ($candidate !== '' && filter_var($candidate, FILTER_VALIDATE_IP)) {
                        return $candidate; // left-most valid = original client
                    }
                }
            }
        }
        return $remote;
    }

    /**
     * Whitelist check with CIDR support (IPv4 and IPv6). Whitelisted IPs are
     * never sent to the API and are always allowed.
     *
     * @param string $ip
     * @param array  $list
     * @return bool
     */
    function ipblock_guard_is_whitelisted($ip, $list)
    {
        if ($ip === '' || empty($list)) {
            return false;
        }
        foreach ($list as $entry) {
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }
            if (strpos($entry, '/') === false) {
                if ($ip === $entry) {
                    return true;
                }
                continue;
            }
            if (ipblock_guard_cidr_match($ip, $entry)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Match an IP against a CIDR range. Works for both IPv4 and IPv6.
     */
    function ipblock_guard_cidr_match($ip, $cidr)
    {
        list($subnet, $bits) = array_pad(explode('/', $cidr, 2), 2, null);
        if ($bits === null || !is_numeric($bits)) {
            return false;
        }
        $bits = (int) $bits;

        $ipBin     = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);
        if ($ipBin === false || $subnetBin === false) {
            return false;
        }
        // Different address families never match.
        if (strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $bytes = intdiv($bits, 8);
        $rem   = $bits % 8;

        if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
            return false;
        }
        if ($rem === 0) {
            return true;
        }
        $mask = ~((1 << (8 - $rem)) - 1) & 0xFF;
        return (ord($ipBin[$bytes]) & $mask) === (ord($subnetBin[$bytes]) & $mask);
    }

    /**
     * Cache directory used when APCu is unavailable. Isolated per site_id so
     * decisions never leak between hosting accounts.
     */
    function ipblock_guard_cache_dir($cfg)
    {
        $base = sys_get_temp_dir() . '/ipblock_cache_' . substr(md5($cfg['site_id']), 0, 12);
        if (!is_dir($base)) {
            @mkdir($base, 0700, true);
        }
        return $base;
    }

    /**
     * Read a cached decision for this IP. Returns 'allow', 'block' or null (miss).
     */
    function ipblock_guard_cache_get($cfg, $ip)
    {
        if ($cfg['cache_ttl'] <= 0) {
            return null;
        }
        $cacheKey = 'ipblock:' . $cfg['site_id'] . ':' . $ip;

        if (function_exists('apcu_fetch')) {
            $ok  = false;
            $val = apcu_fetch($cacheKey, $ok);
            return $ok ? $val : null;
        }

        $file = ipblock_guard_cache_dir($cfg) . '/' . md5($ip) . '.dec';
        if (!is_file($file)) {
            return null;
        }
        if ((time() - @filemtime($file)) > $cfg['cache_ttl']) {
            @unlink($file);
            return null;
        }
        $val = @file_get_contents($file);
        return ($val === 'block' || $val === 'allow') ? $val : null;
    }

    /**
     * Persist a decision for this IP for cache_ttl seconds.
     */
    function ipblock_guard_cache_put($cfg, $ip, $decision)
    {
        if ($cfg['cache_ttl'] <= 0) {
            return;
        }
        $cacheKey = 'ipblock:' . $cfg['site_id'] . ':' . $ip;

        if (function_exists('apcu_store')) {
            @apcu_store($cacheKey, $decision, $cfg['cache_ttl']);
            return;
        }

        $file = ipblock_guard_cache_dir($cfg) . '/' . md5($ip) . '.dec';
        @file_put_contents($file, $decision, LOCK_EX);
    }

    /**
     * Call the IP-Block.com API. Returns 'allow', 'block' or null.
     *   null  => could not get a definitive answer (caller applies fail_open)
     *   'block' => API explicitly said block
     *   'allow' => API explicitly said allow
     *
     * Hard 1-second timeout. Uses cURL when available, otherwise a stream.
     */
    function ipblock_guard_api_call($cfg, $ip)
    {
        $payload = json_encode(array(
            'api_key'    => $cfg['api_key'],
            'site_id'    => $cfg['site_id'],
            'ip'         => $ip,
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
            'referrer'   => isset($_SERVER['HTTP_REFERER'])    ? $_SERVER['HTTP_REFERER']    : '',
        ));

        $body   = null;
        $status = 0;

        if (function_exists('curl_init')) {
            $ch = curl_init($cfg['api_url']);
            curl_setopt_array($ch, array(
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $payload,
                CURLOPT_HTTPHEADER     => array('Content-Type: application/json'),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 1,   // total hard cap: 1 second
                CURLOPT_CONNECTTIMEOUT => 1,
                CURLOPT_NOSIGNAL       => true, // sub-second timeouts under threads
                CURLOPT_FOLLOWLOCATION => false,
            ));
            $body   = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($body === false) {
                return null; // connection error / timeout -> fail open
            }
        } else {
            // Fallback: stream context (still 1s timeout).
            $ctx = stream_context_create(array('http' => array(
                'method'        => 'POST',
                'header'        => "Content-Type: application/json\r\n",
                'content'       => $payload,
                'timeout'       => 1,
                'ignore_errors' => true,
            )));
            $body = @file_get_contents($cfg['api_url'], false, $ctx);
            if ($body === false) {
                return null;
            }
            // Parse status line from $http_response_header.
            $status = 0;
            if (isset($http_response_header[0]) &&
                preg_match('#\s(\d{3})\s#', $http_response_header[0], $m)) {
                $status = (int) $m[1];
            }
        }

        // Only trust 2xx responses.
        if ($status < 200 || $status >= 300) {
            return null;
        }

        $data = json_decode($body, true);
        if (!is_array($data) || !isset($data['action'])) {
            return null; // missing action -> fail open
        }
        return ($data['action'] === 'block') ? 'block' : 'allow';
    }

    /**
     * Send the block response and stop the request. Either an HTTP 403 with a
     * short message, or a redirect to the configured blocked page.
     */
    function ipblock_guard_deny($cfg)
    {
        if (headers_sent()) {
            // Cannot alter headers; best effort stop.
            exit;
        }
        if ($cfg['block_action'] === 'redirect') {
            header('Location: ' . $cfg['redirect_url'], true, 302);
            exit;
        }
        header('HTTP/1.1 403 Forbidden');
        header('Status: 403 Forbidden');
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        $msg = htmlspecialchars($cfg['block_message'], ENT_QUOTES, 'UTF-8');
        echo '<!doctype html><html><head><meta charset="utf-8"><title>403 Forbidden</title></head>'
           . '<body style="font-family:sans-serif;text-align:center;padding:60px;">'
           . '<h1>403 Forbidden</h1><p>' . $msg . '</p>'
           . '<p style="color:#888;font-size:12px;">Protected by IP-Block.com</p>'
           . '</body></html>';
        exit;
    }

    /**
     * Main entry point. Orchestrates the full check with a hard fail-open
     * fallback: any unexpected exception simply allows the request.
     */
    function ipblock_guard_run()
    {
        try {
            if (!ipblock_guard_is_web_request()) {
                return; // CLI / cron / no client -> never interfere
            }

            $cfg = ipblock_guard_config();
            if ($cfg === null) {
                return; // disabled / no config / bad config -> allow
            }

            $ip = ipblock_guard_client_ip($cfg);
            if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
                return; // cannot determine a valid IP -> allow
            }

            if (ipblock_guard_is_whitelisted($ip, $cfg['whitelist'])) {
                return; // trusted -> allow, no API call
            }

            // 1) Cache.
            $decision = ipblock_guard_cache_get($cfg, $ip);

            // 2) API (only on cache miss).
            if ($decision === null) {
                $decision = ipblock_guard_api_call($cfg, $ip);

                if ($decision === null) {
                    // No definitive answer. Honour fail_open.
                    if ($cfg['fail_open']) {
                        return;            // allow
                    }
                    ipblock_guard_deny($cfg); // fail closed -> block
                    return;
                }
                // Cache the definitive answer.
                ipblock_guard_cache_put($cfg, $ip, $decision);
            }

            if ($decision === 'block') {
                ipblock_guard_deny($cfg);
            }
            // 'allow' -> fall through, request continues.
        } catch (\Throwable $e) {
            // PHP 7+ : never let the guard break a site.
            return;
        } catch (\Exception $e) {
            return;
        }
    }
}

// Run immediately on prepend.
ipblock_guard_run();
