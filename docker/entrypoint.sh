#!/usr/bin/env sh
# Entrypoint: forward all arguments to the vulnpipe CLI.
set -eu
exec vulnpipe "$@"
