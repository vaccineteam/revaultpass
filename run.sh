#!/usr/bin/env bash
cd "$(dirname "$0")"
exec ./target/release/revaultpass "$@"
