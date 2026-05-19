# telemt project memory

Deploy + operational notes that should survive context resets.

## Production VPS

- **Host:** `pr2.fluxsolutions.ru`
- **Source checkout:** `/etc/telemt/` (yes — the repo lives next to the config file; install.sh from PR #4 puts it here)
- **Installed binary:** `/opt/telemt/bin/telemt`
- **Config:** `/etc/telemt/telemt.toml`
- **Service:** systemd unit `telemt` (`systemctl status telemt`)
- **API:** `http://127.0.0.1:8888/v1/*`
- **6 outbound IPs (bind_addresses):** `45.144.53.{36,77,100,124,142,143}`

## Deploy script

Local copy: `/tmp/deploy-phase2.sh` (regenerate when re-deploying — temp dir).
- Finds source at `/etc/telemt` first.
- Backs up binary + config with timestamp before swap.
- Auto-rolls-back if service fails to start after swap.
- Inserts/updates `me_writer_bind_mode = "shard"` idempotently.

## Telegram bot

Repo: `Gickrede-e/telemt-bot` (separate public repo).
Deployed at `/opt/telemt-bot/bot.py` on the same VPS, env vars `TELEMT_BOT_TOKEN` + `TELEMT_BOT_OWNERS=5136562786`.

**Bot user must be in `telemt` group** for `read_shard_config()` to read `/etc/telemt/telemt.toml` (mode `rw-r----- root:telemt`). On fresh install: `usermod -aG telemt telemt-bot && systemctl restart telemt-bot`. Without this, `/shards` and the shard line in `/status` fall back to "unknown" mode (live /proc/net/tcp still works).

Deploy workflow:
```
curl -fsSL https://raw.githubusercontent.com/Gickrede-e/telemt-bot/main/bot.py -o /opt/telemt-bot/bot.py
chown telemt-bot:telemt-bot /opt/telemt-bot/bot.py
systemctl restart telemt-bot
```

## PR target

**All PRs go to the fork `Gickrede-e/telemt_bb`, never to upstream `telemt/telemt`.**

## Phase 2 status (as of 2026-05-19)

Merged to main:
- PR #11 (Phase 2a): MePoolMux scaffold + `me_writer_bind_mode` flag + `override_bind` connect-chain plumbing
- PR #12 (Phase 2b): N-pool construction, listener routing, per-shard background tasks
- PR #13 (Phase 2c): system-wide stats aggregation across shards

Production setting on VPS: still `me_writer_bind_multiplier = 6` (single pool, 6× writers).
Shard mode (`me_writer_bind_mode = "shard"`) not yet activated — deploy pending.
