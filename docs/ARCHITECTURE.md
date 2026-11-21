# Architecture

## Components

```
MainActivity (Compose UI)
  └─ AppShell
       ├─ Workflow tab (discover / fingerprint / check / run)
       ├─ Sessions tab (SQLite history + JSON export)
       └─ Setup tab (chroot + engine paths)
            │
            ▼
engineCall() → su -c "chroot <path> python3 <engine_cli.py> <command> ..."
            │
            ▼
engine_cli.py (JSON-only stdout)
  ├─ doctor     → verify EmbedXPL import and module count
  ├─ discover   → NetworkDiscovery.scan()
  ├─ fingerprint→ NetworkDiscovery on one host + module matching
  ├─ check      → exploit.check() (read-only)
  └─ run        → exploit.run() (guarded)
            │
            ▼
EmbedXPL-Forge (/opt/EmbedXPL-Forge)
```

## Safety boundaries

1. The UI never auto-targets anything. A CIDR or IP must be entered.
2. `check` is the default action and does not invoke `run()`.
3. `run` requires:
   - `--confirm I_AUTHORIZE` from the app,
   - target inside `allowed_networks.json`,
   - user retyping the target IP in a dialog.
4. Interactive prompts inside modules are disabled in the bridge.
5. Every command result is written to a local SQLite table for auditability.

## Data handling

- No network data leaves the device except what the selected EmbedXPL module
  sends to the explicitly chosen target.
- Results are stored locally in `routerxpl_results.db`.
- JSON export is user-initiated via Android share sheet.

## Build

`android/gradlew assembleDebug` produces the APK. Release builds should be
signed with a maintainer-owned key and published via CI, not committed.
