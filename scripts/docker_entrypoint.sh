#!/bin/sh
# Copy the committed ChromaDB into a writable temporary directory so the
# container root filesystem can be read-only.
set -eu

if [ "${CHROMA_WRITABLE_COPY:-0}" = "1" ]; then
    mkdir -p /tmp/chroma
    cp -a /app/data/chromadb/. /tmp/chroma/
    export CHROMA_PATH=/tmp/chroma
fi

exec "$@"
