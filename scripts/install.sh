#!/usr/bin/env bash
# Cathedral validator installer. Downloads the signed updater bootstrap,
# verifies it against the bootstrap signing key pinned below, and installs it
# as root-owned files. It installs no release and enables no service.
#
# Run: sudo bash install.sh
#
# Maintainers: regenerate by substituting per-publication values only.
# See docs/RELEASE_MAINTAINER.md.
set -euo pipefail
sudo apt-get update && sudo apt-get install -y ca-certificates curl openssl python3.12 python3.12-venv
BASE=https://github.com/cathedralai/cathedral-validator/releases/download/validator-bootstrap-production-s4-649e3a887d37bc220f16a80e58721c81188b30572d6319ebd9ba4dfa27f589e8
BOOTSTRAP_DIR=$(sudo /usr/bin/mktemp -d /var/tmp/cathedral-bootstrap.XXXXXXXXXX)
cleanup() {
  if [[ ! "$BOOTSTRAP_DIR" =~ ^/var/tmp/cathedral-bootstrap\.[[:alnum:]]{10}$ ]]; then
    printf 'refusing unsafe bootstrap cleanup path: %s\n' "$BOOTSTRAP_DIR" >&2
    return 1
  fi
  sudo /usr/bin/rm -rf -- "$BOOTSTRAP_DIR"
}
trap 'printf "bootstrap staging kept for inspection: %s\n" "$BOOTSTRAP_DIR" >&2' ERR
for f in updater-bootstrap.tar.gz updater-bootstrap.manifest.json updater-bootstrap.manifest.sig bootstrap-signing-public-key.pem; do
  sudo curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --output "$BOOTSTRAP_DIR/$f" "$BASE/$f"
done
printf '%s  %s\n' \
  '06635e7eb448acb037a505db5daccb702f7dd998d9c65d32c9ef20766b0b7f90' "$BOOTSTRAP_DIR/updater-bootstrap.tar.gz" \
  '649e3a887d37bc220f16a80e58721c81188b30572d6319ebd9ba4dfa27f589e8' "$BOOTSTRAP_DIR/updater-bootstrap.manifest.json" \
  '262872ffc0273e69459763e2f8afc839f976a7e18cea0e1208232744d57aa46a' "$BOOTSTRAP_DIR/updater-bootstrap.manifest.sig" \
  '390a10b2e18f1d9eeffd5146e166cc518cc13bb03c6f2784c101456d8042809e' "$BOOTSTRAP_DIR/bootstrap-signing-public-key.pem" \
  | sudo sha256sum --check --strict
test "sha256:$(sudo openssl pkey -pubin -in "$BOOTSTRAP_DIR/bootstrap-signing-public-key.pem" -outform DER | sha256sum | cut -d' ' -f1)" = sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013
sudo openssl pkeyutl -verify -pubin -inkey "$BOOTSTRAP_DIR/bootstrap-signing-public-key.pem" \
  -rawin -in "$BOOTSTRAP_DIR/updater-bootstrap.manifest.json" \
  -sigfile "$BOOTSTRAP_DIR/updater-bootstrap.manifest.sig"
sudo /usr/bin/python3.12 - \
  "$BOOTSTRAP_DIR/updater-bootstrap.manifest.json" \
  "$BOOTSTRAP_DIR/updater-bootstrap.tar.gz" <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
bundle_path = Path(sys.argv[2])
manifest = json.loads(manifest_path.read_text(encoding="ascii"))
bundle_claim = manifest.get("bundle")
if not isinstance(bundle_claim, dict):
    raise SystemExit("signed manifest has no bundle claim")
expected_size = bundle_claim.get("size")
expected_sha256 = bundle_claim.get("sha256")
if type(expected_size) is not int or expected_size < 1:
    raise SystemExit("signed manifest has an invalid bundle size")
if (
    not isinstance(expected_sha256, str)
    or len(expected_sha256) != 64
    or any(character not in "0123456789abcdef" for character in expected_sha256)
):
    raise SystemExit("signed manifest has an invalid bundle digest")
with bundle_path.open("rb") as stream:
    actual_size = os.fstat(stream.fileno()).st_size
    actual_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
if actual_size != expected_size or actual_sha256 != expected_sha256:
    raise SystemExit("bundle does not match the signed manifest")
PY
sudo sh -c 'tar -xOf "$1" payload/installer/install_updater_bundle.py > "$2"' sh \
  "$BOOTSTRAP_DIR/updater-bootstrap.tar.gz" "$BOOTSTRAP_DIR/install_updater_bundle.py"
sudo /usr/bin/python3.12 "$BOOTSTRAP_DIR/install_updater_bundle.py" \
  --bundle "$BOOTSTRAP_DIR/updater-bootstrap.tar.gz" \
  --manifest "$BOOTSTRAP_DIR/updater-bootstrap.manifest.json" \
  --signature "$BOOTSTRAP_DIR/updater-bootstrap.manifest.sig" \
  --bootstrap-public-key "$BOOTSTRAP_DIR/bootstrap-signing-public-key.pem" \
  --expected-bootstrap-key-fingerprint sha256:9339edaba134edcea3b7f84e15a1f3b853b173be2cc645dbc6898c06ba996013 \
  --minimum-bootstrap-sequence 4
cleanup
trap - ERR
