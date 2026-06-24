#!/usr/bin/env sh
# vulnpipe container entrypoint.
#
# Before a `scan` runs, wait for the OWASP ZAP daemon's API to answer, then forward
# all arguments to the vulnpipe CLI. Other subcommands (report / diff / baseline /
# --help) do not need ZAP and run immediately.
#
# Environment:
#   ZAP_API_URL        ZAP daemon base URL (default http://zap:8080)
#   ZAP_API_KEY        ZAP API key (must match the daemon's configured key)
#   ZAP_WAIT           set to 0 to skip the readiness wait (default 1)
#   ZAP_WAIT_RETRIES   number of 2s polls before giving up (default 60)
set -eu

ZAP_API_URL="${ZAP_API_URL:-http://zap:8080}"

wait_for_zap() {
    if [ "${ZAP_WAIT:-1}" = "0" ]; then
        return 0
    fi
    retries="${ZAP_WAIT_RETRIES:-60}"
    url="${ZAP_API_URL%/}/JSON/core/view/version/?apikey=${ZAP_API_KEY:-}"
    printf 'vulnpipe: waiting for ZAP at %s ...\n' "$ZAP_API_URL" >&2
    i=0
    while [ "$i" -lt "$retries" ]; do
        if curl -fsS "$url" >/dev/null 2>&1; then
            echo 'vulnpipe: ZAP is ready' >&2
            return 0
        fi
        i=$((i + 1))
        sleep 2
    done
    echo "vulnpipe: ZAP did not become ready at $ZAP_API_URL after $retries attempts" >&2
    return 1
}

case "${1:-}" in
    scan) wait_for_zap ;;
esac

exec vulnpipe "$@"
