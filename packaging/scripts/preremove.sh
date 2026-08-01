#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
	systemctl stop route53-dnsweaver-webhook.service >/dev/null 2>&1 || true
	systemctl disable route53-dnsweaver-webhook.service >/dev/null 2>&1 || true
fi
