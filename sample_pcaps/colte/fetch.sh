#!/usr/bin/env bash
# Fetch the CoLTE PCAP library and extract the successful-initial-attach
# capture. We do not redistribute the pcap; it is downloaded from the
# CoLTE blog on demand and verified by SHA-256.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
URL="https://blog.colte.network/wp-content/uploads/2020/03/pcaps.zip"
ZIP_SHA256="369c3b3910f166851063e3b95e973c537568567b928a0774df180a847c1c323f"
PCAP_SHA256="925d6927d8db45c46112443b1371d6998c2540cc8d54a65a09a75a591b5d647f"
TARGET="$HERE/2_firstattach.pcap"

if [[ -f "$TARGET" ]] && \
   [[ "$(sha256sum "$TARGET" | awk '{print $1}')" == "$PCAP_SHA256" ]]; then
    echo "already present, hash ok: $TARGET"
    exit 0
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "downloading $URL"
curl -sSL -o "$TMP/pcaps.zip" "$URL"

got="$(sha256sum "$TMP/pcaps.zip" | awk '{print $1}')"
if [[ "$got" != "$ZIP_SHA256" ]]; then
    echo "zip hash mismatch: got $got expected $ZIP_SHA256" >&2
    exit 1
fi

unzip -p "$TMP/pcaps.zip" pcaps/2_firstattach.pcap > "$TARGET"

got="$(sha256sum "$TARGET" | awk '{print $1}')"
if [[ "$got" != "$PCAP_SHA256" ]]; then
    echo "pcap hash mismatch: got $got expected $PCAP_SHA256" >&2
    rm -f "$TARGET"
    exit 1
fi

echo "ok: $TARGET"
