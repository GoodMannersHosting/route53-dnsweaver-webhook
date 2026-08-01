#!/bin/sh
set -e

# Make systemd aware of the unit the package just dropped in. Deliberately
# not enabled or started: the service needs a hosted zone id in
# /etc/default/route53-dnsweaver-webhook first, and starting it without one
# would only produce a failed unit.
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi
