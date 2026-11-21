#!/bin/bash
# Run this ONCE inside the Kali NetHunter chroot (as root).
# It installs EmbedXPL-Forge and the JSON bridge used by the APK.
set -euo pipefail

REPO_DIR="/opt/RouterXPL-Forge"
EXF_DIR="/opt/EmbedXPL-Forge"

echo "[*] RouterXPL-Forge engine installer (NetHunter chroot)"
[ "$(id -u)" -eq 0 ] || { echo "[!] Run as root"; exit 1; }

if [ ! -d "$EXF_DIR/.git" ]; then
  echo "[*] Cloning EmbedXPL-Forge..."
  git clone --depth 1 https://github.com/Zeeeepa/EmbedXPL-Forge.git "$EXF_DIR"
else
  echo "[*] EmbedXPL-Forge already present, skipping clone."
fi

echo "[*] Installing Python dependencies..."
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install "$EXF_DIR"

echo "[*] Installing lab allowlist template..."
if [ ! -f "$REPO_DIR/engine/allowed_networks.json" ]; then
  cp "$REPO_DIR/engine/allowed_networks.example.json" "$REPO_DIR/engine/allowed_networks.json"
  echo "[!] Edit $REPO_DIR/engine/allowed_networks.json with YOUR lab CIDRs."
fi

echo "[*] Verifying engine..."
python3 "$REPO_DIR/engine/engine_cli.py" doctor

echo "[+] Done. The APK can now run commands inside this chroot."
