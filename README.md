# RouterXPL-Forge (NetHunter APK)

An Android controller app for **authorized** router / embedded-device security testing. It drives the full
[EmbedXPL-Forge](https://github.com/Zeeeepa/EmbedXPL-Forge) module set from a rooted Kali NetHunter phone.

> **Scope:** lab / owned devices or devices you have explicit written permission to test only.
> The app refuses to run exploits unless the target is inside your own `allowed_networks.json` and you
> retype the target IP in a confirmation dialog.

## Built artifact

- APK: `/opt/RouterXPL-Forge/RouterXPL-Forge.apk`
- CI artifact: download `RouterXPL-Forge-debug` from the latest successful **Actions** run
- Debug-signed, `minSdk 24`, `targetSdk 35`, package `com.routerxpl.forge`

Install on the phone:

```bash
adb install -r /opt/RouterXPL-Forge/RouterXPL-Forge.apk
```

or copy the APK to the phone and open it, allowing installation of unknown apps.

## Architecture

```
Android APK (Kotlin + Jetpack Compose / Material 3)
   |  su -c "chroot /kali python3 /opt/.../engine_cli.py <command> ..."
   v
Kali NetHunter chroot
   |  JSON CLI bridge: engine/engine_cli.py
   v
EmbedXPL-Forge (/opt/EmbedXPL-Forge)
   - NetworkDiscovery  -> discovery + fingerprinting
   - index_modules / import_exploit -> module selection
   - check() / run()   -> vulnerability checks and exploits
```

The APK has no Python runtime inside it. It uses the real Kali chroot, so all EmbedXPL modules work.

## One-time NetHunter setup

Run these **inside the Kali chroot as root**:

```bash
# Put this folder in the chroot first, e.g. from Android:
#   cp -r /sdcard/RouterXPL-Forge /opt/RouterXPL-Forge

cd /opt/RouterXPL-Forge
bash engine/install.sh
nano engine/allowed_networks.json     # set YOUR lab CIDRs, e.g. 192.168.1.0/24
python3 engine/engine_cli.py doctor   # should report ok:true and module count
```

`install.sh` clones EmbedXPL-Forge to `/opt/EmbedXPL-Forge`, installs its Python dependencies, and creates
`allowed_networks.json` from the template.

In the APK, open **Setup** and keep the defaults:

- Chroot path: `/kali`
- Engine CLI path: `/opt/RouterXPL-Forge/engine/engine_cli.py`

If your NetHunter chroot lives elsewhere (some installs use `/kali-arm64`), change the chroot path here.

## App workflow

1. **Discover live devices** — enter a CIDR (e.g. `192.168.1.0/24`) and tap *Discover*.
   Uses EmbedXPL's ARP / nmap / masscan / scapy / socket pipeline.
2. **Fingerprint + select modules** — tap a discovered host. The app fingerprints it (vendor, model,
   ports, confidence) and lists only modules matched to that fingerprint.
3. **Run vulnerability checks / exploits** — tap a module, then:
   - *Safe check* → calls `module.check()` (read-only probe).
   - *Run exploit* → requires a confirm dialog where you must retype the target IP, plus the target must
     be inside `allowed_networks.json`.
4. **Sessions and results** — every check/run is stored in a local SQLite DB. Use *Sessions* to review
   and *Share JSON* to export a report.

## Safety behavior

- `check` is the default and is always non-destructive.
- `run` is blocked unless all of these are true:
  - you selected an explicit target and module,
  - you confirmed by retyping the target IP,
  - the target is inside a CIDR you declared in `allowed_networks.json`,
  - you passed `--confirm I_AUTHORIZE` (the app does this only after confirmation).
- Interactive prompts inside modules are disabled so a module cannot hang waiting for input.
- Results are logged locally with timestamp, command, target, module, and output.

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

- Discovery quality depends on root, `nmap`/`masscan`/`scapy` availability in the chroot, and network
  reachability. On some Wi-Fi chipsets ARP scanning is unreliable; nmap fallback still works.
- Some EmbedXPL modules require extra hardware or credentials; those modules will report an error.
- The APK is debug-signed. For distribution, generate your own signing key and build a release APK.
- No automatic update mechanism. Re-run `engine/install.sh` after pulling newer EmbedXPL sources.
