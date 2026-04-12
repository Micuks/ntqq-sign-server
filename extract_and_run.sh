#!/bin/bash
# Self-contained NTQQ Sign Server
# Extracts compressed wrapper.node and starts the server

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WRAPPER="$SCRIPT_DIR/wrapper.node"
WRAPPER_GZ="$SCRIPT_DIR/wrapper.node.gz"

# Extract if needed
if [ ! -f "$WRAPPER" ] && [ -f "$WRAPPER_GZ" ]; then
    echo "[*] Extracting wrapper.node..."
    gunzip -k "$WRAPPER_GZ"
fi

# Build libsymbols.so if needed
if [ ! -f "$SCRIPT_DIR/libsymbols.so" ]; then
    echo "[*] Building libsymbols.so..."
    gcc -std=c99 -shared -fPIC -o "$SCRIPT_DIR/libsymbols.so" "$SCRIPT_DIR/symbols.c"
fi

# Run server
export LD_LIBRARY_PATH="$SCRIPT_DIR:$LD_LIBRARY_PATH"
exec python3 "$SCRIPT_DIR/sign.py" --wrapper "$WRAPPER" "$@"
