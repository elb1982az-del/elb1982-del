# RouterXPL-Forge (NetHunter APK)
> ⚠️ **WARNING: AUTHORIZED LAB USE ONLY**
> This tool is designed for security testing on devices and networks you explicitly own or have written permission to test. The author is not responsible for any misuse or illegal activity.
An Android controller app for **authorized** router / embedded-device security testing. It drives the full
[EmbedXPL-Forge](https://github.com/Zeeeepa/EmbedXPL-Forge) module set from a rooted Kali NetHunter phone.

> **Scope:** lab / owned devices or devices you have explicit written permission to test only.
> The app refuses to run exploits unless the target is inside your own allowlist CIDR and you
> retype the target IP in a confirmation dialog.

## Built artifact

- APK: `/opt/RouterXPL-Forge/RouterXPL-Forge.apk`
- Phone copy: `/sdcard/Download/RouterXPL-Forge.apk`
- MD5 of current verified build: `3e9d1e377e869fc25f71709508da0bfb`
- CI artifact: download `RouterXPL-Forge-debug` from the latest successful **Actions** run
- Debug-signed, `minSdk 24`, `targetSdk 35`, package `com.routerxpl.forge`

Install on the phone:

```bash
adb install -r /opt/RouterXPL-Forge/RouterXPL-Forge.apk
```

or copy the APK to the phone and open it, allowing installation of unknown apps. After reinstalling,
re-grant root access to the new app UID in Magisk / KernelSU.

## Architecture

```
Android APK (Kotlin + Jetpack Compose / Material 3)
   |  su -c "chroot <kali-chroot> /opt/RouterXPL-Forge/.venv/bin/python \
   |          /opt/RouterXPL-Forge/engine/engine_cli.py <command> ..."
   v
Kali NetHunter chroot
   |  JSON CLI bridge: engine/engine_cli.py
   |    allow       -> write the active lab CIDR allowlist
   |    discover    -> ARP / nmap / scapy discovery
   |    fingerprint -> host fingerprint + ranked modules
   |    check / run -> safe checks / guarded exploits
   |    wol         -> guarded Wake-on-LAN
   v
EmbedXPL-Forge (/opt/EmbedXPL-Forge)
```

The APK has no Python runtime inside it. It uses the real Kali chroot, so all EmbedXPL modules work.

## One-time NetHunter setup

Run these **inside the Kali chroot as root**:

```bash
# Put this folder in the chroot first, e.g. from Android:
#   cp -r /sdcard/RouterXPL-Forge /opt/RouterXPL-Forge

cd /opt/RouterXPL-Forge
bash engine/install.sh
python3 engine/engine_cli.py doctor   # should report ok:true and module count
```

`install.sh` clones EmbedXPL-Forge to `/opt/EmbedXPL-Forge`, installs its Python dependencies, and creates
`allowed_networks.json` from the template.

You do **not** need to edit `allowed_networks.json` with nano anymore. Type the lab CIDR in the app and tap
**Discover**; the app writes the file for you before scanning. To do the same from the CLI:

```bash
.venv/bin/python engine/engine_cli.py allow --network 192.168.0.0/24
```

In the APK, open **Setup** and keep the defaults:

- Chroot path: `/data/local/nhsystem/kali-arm64`
- Engine CLI path: `/opt/RouterXPL-Forge/engine/engine_cli.py`
- Python path: `/opt/RouterXPL-Forge/.venv/bin/python`

If your NetHunter chroot lives elsewhere (some installs use `/kali-arm64`), change the chroot path here.

## App workflow

1. **Discover live devices** — type a private IPv4 CIDR such as `192.168.0.0/24`, then tap **Discover**.
   The app first writes that CIDR to `allowed_networks.json` (replacing the previous allowlist), then runs
   EmbedXPL's ARP / nmap / scapy discovery pipeline. Only RFC1918 ranges are accepted:
   `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` and their subnets. A host address like
   `192.168.0.5/24` is normalized to `192.168.0.0/24`.
2. **Fingerprint + ranked modules** — tap a discovered host. The app fingerprints it (vendor, model,
   ports, confidence) and lists only modules matched to that fingerprint. Modules are sorted by relevance
   score; likely failures are marked **LIKELY FAIL** in red with the reason shown.
3. **Run vulnerability checks / exploits** — tap a module, then:
   - *Safe check* → calls `module.check()` (read-only probe).
   - *Run exploit* → requires a confirm dialog where you must retype the target IP, plus the target must
     be inside the CIDR written by Discover.
4. **Sleeping devices / Wake-on-LAN** — devices seen in earlier discoveries are saved locally. Devices
   missing from the latest scan appear under *Sleeping / offline devices*. WoL requires its own confirm
   dialog and only sends to previously discovered devices with a valid MAC inside the last scanned CIDR.
5. **Sessions and results** — every check/run is stored in a local SQLite DB. Use *Sessions* to review
   and *Share JSON* to export a report.

## Safety behavior

- `check` is the default and is always non-destructive.
- The Discover-supplied allowlist accepts only RFC1918 IPv4 CIDRs. Public ranges and bare IPs without a
  prefix are rejected.
- Discover **replaces** the allowlist with the typed CIDR. If you change networks, run Discover on the new
  CIDR so checks and exploits are scoped to it.
- `run` is blocked unless all of these are true:
  - you selected an explicit target and module,
  - you confirmed by retyping the target IP,
  - the target is inside the active allowlist CIDR,
  - you passed `--confirm I_AUTHORIZE` (the app does this only after confirmation).
- WoL is blocked unless the MAC came from a previously discovered device and is inside the last scanned
  CIDR.
- Interactive prompts inside modules are disabled so a module cannot hang waiting for input.
- Results are logged locally with timestamp, command, target, module, and output.

## Runtime fixes included

- Discovery skips incomplete / stale ARP entries such as `<incomplete>` instead of treating them as live
  hosts and scanning the whole subnet.
- Multi-host nmap uses faster open-port detection; slow version/OS detection was removed from that path.
  Fingerprinting still performs detailed banner grabbing separately.
- URL building no longer duplicates paths/query strings in HTTP module requests.
- Blank fingerprint vendor/model/module text falls back to `Unknown` in the UI.
- Upstream changes are tracked in `patches/embedxpl-runtime-fixes.patch`.

## Rebuild from source

The repo includes a Gradle wrapper. On a normal x86_64 host:

```bash
cd android
./gradlew assembleDebug
```

On an arm64 Linux host where Google's `aapt2` is x86_64, run it through qemu and pass the override
on the command line (do **not** commit this path):

```bash
./gradlew assembleDebug -Pandroid.aapt2FromMavenOverride=/opt/aapt2
```

CI builds on x86_64 and does not need the override. Generated APKs are git-ignored; release artifacts
should come from CI or a signed local release build.

## Limitations

- The app-managed allowlist holds one active CIDR. Discover again on another CIDR to switch scope; a CIDR
  may be allowed but unreachable if the phone is not connected or routed to that network.
- Discovery quality depends on root, `nmap`/`masscan`/`scapy` availability in the chroot, and network
  reachability. On some Wi-Fi chipsets ARP scanning is unreliable; nmap fallback still works.
- Some EmbedXPL modules require extra hardware or credentials; those modules will report an error.
- The APK is debug-signed. For distribution, generate your own signing key and build a release APK.
- No automatic update mechanism. Re-run `engine/install.sh` after pulling newer EmbedXPL sources.
