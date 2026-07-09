> ⚠️ **Status: untested.** This extension is provided as-is and has **not been tested in production**. Please feel free to fork, modify, improve, and open pull requests.
>
> Licensed under **GNU GPLv3** (see [LICENSE](LICENSE)).

# IP-Block.com for Plesk

A Plesk extension that screens every visitor to **all hosted domains** against
the IP-Block.com API and blocks bad IPs before your customers' PHP applications
run. Managed from a native Plesk settings page.

- **Panel:** Plesk Obsidian
- **Version targeted:** 18.0.76 (2026). Requires `plesk_min_version` 18.0.0+.
- **Extension type:** `pm_Settings` PHP controller (settings page) + drop-in
  PHP enforcement guard (`auto_prepend_file`).

## What it does

```
POST https://api.ip-block.com/v1/check
Content-Type: application/json
{"api_key","site_id","ip","user_agent","referrer"}   ->   {"action":"allow|block"}
```

A visitor is blocked **only** when `action === "block"`. Hard **1 second**
timeout; **fails open** (visitor allowed) on any error/timeout/non-2xx/missing
action by default. Per-IP decisions are cached (APCu or temp file) for
`cache_ttl` seconds. CLI and cron are never screened.

## Package layout (`src/`)

```
src/
├── meta.xml                              # Plesk manifest
└── plib/
    ├── controllers/IndexController.php    # Settings page (pm_Controller_Action)
    ├── library/Config.php                 # pm_Settings <-> JSON config bridge
    ├── resources/ipblock-guard.php        # Shared enforcement guard
    ├── scripts/post-install.php           # Installs guard + auto_prepend (root)
    ├── scripts/pre-uninstall.php          # Removes guard + auto_prepend (root)
    └── views/scripts/index/index.phtml    # Settings view
```

At runtime:

| Path | Purpose |
|------|---------|
| `/opt/ipblock/ipblock-guard.php` | Installed guard (auto_prepend target) |
| `/usr/local/psa/var/modules/ipblock/config.json` | Config the guard reads |
| `/opt/plesk/php/*/etc/php.d/zzz-ipblock.ini` | Registers auto_prepend per PHP handler |

## Build the package

Zip the **contents** of `src/` (so `meta.xml` is at the archive root):

```bash
cd src
zip -r ../ipblock-1.0.0-1.zip meta.xml plib
```

## Install

**Plesk UI:** Extensions > My Extensions > *Upload Extension* > choose
`ipblock-1.0.0-1.zip`.

**CLI:**
```bash
plesk bin extension --install ipblock-1.0.0-1.zip
```

The `post-install` hook (run as root by Plesk) installs the guard, creates a
default config (protection **disabled**), registers `auto_prepend_file` for
every Plesk PHP handler, and reloads the web server.

Then open **Extensions > IP-Block Protection**, enter your **Site ID** and
**API Key**, tick **Enable protection**, and Save.

## Configuration (settings page)

| Setting | Default | Notes |
|---------|---------|-------|
| Enable protection | off | Master switch |
| Site ID / API Key | — | From your ip-block.com account |
| API URL | `https://api.ip-block.com/v1/check` | |
| Fail open | on | Allow visitors when API unreachable (recommended) |
| Cache TTL | 300 | Seconds to cache per-IP decision |
| Behind proxy / Real-IP header | off / `X-Forwarded-For` | Trust proxy/CDN header for client IP |
| Block action | 403 | `403` page or `redirect` |
| Block message / Redirect URL | `Access denied.` / blocked.php | |
| Whitelist | empty | One IP or CIDR per line; never checked |

## Uninstall

```bash
plesk bin extension --uninstall ipblock
```

The `pre-uninstall` hook removes the guard and the `auto_prepend_file`
registration. The config directory is kept.
