#!/usr/bin/env bash
#
#Name: gh-allow.sh
#Author: SkyWolf
#Date: 11-09-2025
#
#Switcher for internet connection (with own ip address) to toggle restricted lab mode (github + local ssh) and normal mode
#Tested on: Debian 12 (w nftables)

set -Eeuo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH

NFT=${NFT:-$(command -v nft || true)} || { echo "nft not found"; exit 1; }
MODE=${1:-status}

HOST_IP=${HOST_IP:-$(ip r | awk '/^default/ {print $3; exit}')}

GH_DOMAINS=(github.com ssh.github.com api.github.com codeload.github.com raw.githubusercontent.com githubusercontent.com githubcloud.githubusercontent.com objects.githubusercontent.com)

lab_conf() { cat <<EOF
table inet outlock {
  set gh4 { type ipv4_addr; }
  set gh6 { type ipv6_addr; }
  set dns4 {type ipv4_addr; elements = { 10.0.2.3, 1.1.1.1, 9.9.9.9 } }

  chain input {
    type filter hook input priority 0;
    iif lo accept
    ct state established,related accept
    ip saddr $HOST_IP tcp dport 22 accept	#SSH from host
    drop
  }

  chain output {
    type filter hook output priority 0;
    ct state established,related accept
    udp dport 53 ip daddr @dns4 accept
    tcp dport 53 ip daddr @dns4 accept
    ip daddr @gh4 tcp dport {22,443} accept
    ip6 daddr @gh6 tcp dport {22,443} accept
    reject
  }

  chain forward { type filter hook forward priority 0; drop; }
}
EOF
}

normal_conf() { cat <<'EOF'
table inet base {
   chain input { type filter hook input priority 0; iif lo accept; ct state established,related accept; drop; }
   chain output { type filter hook output priority 0; accept; }
   chain forward { type filter hook forward priority 0; drop; }
}
EOF
}

populate_gh() {
	$NFT list table inet outlock >/dev/null 2>&1 || $NFT add table inet outlock
	$NFT list set inet outlock gh4 >/dev/null 2>&1 || $NFT add set inet outlock gh4 '{ type ipv4_addr; }'
	$NFT list set inet outlock gh6 >/dev/null 2>&1 || $NFT add set inet outlock gh6 '{ type ipv6_addr; }'
	$NFT flush set inet outlock gh4 || true
	$NFT flush set inet outlock gh6 || true

	for domain in "${GH_DOMAINS[@]}"; do
		while read -r ip; do
			$NFT add element inet outlock gh4 "{ $ip }" || true
		done < <(getent ahostsv4 "$domain" | awk '{print $1}' | sort -u)
		while read -r a; do
			sudo nft add element inet outlock gh6 "{ $a }" || true
		done < <(getent ahostsv6 "$domain" | awk '{print $1}' | sort -u)
	done
}

apply_lab() {
	echo -e 'nameserver 10.0.2.3\nnameserver 1.1.1.1\nnameserver 9.9.9.9' | sudo tee /etc/resolv.conf
	sudo $NFT flush ruleset
	sudo tee /etc/nftables.conf >/dev/null < <(lab_conf)
	sudo systemctl enable --now nftables
	sudo $NFT -f /etc/nftables.conf
	populate_gh
	echo "[netmode] LAB: Github-only + SSH from host"
}

apply_normal() {
	sudo $NFT flush ruleset
	sudo tee /etc/nftables.conf >/dev/null < <(normal_conf)
	sudo systemctl enable --now nftables
	sudo $NFT -f /etc/nftables.conf
	echo "[netmode] NORMAL: outbound open; inbound default-drop"
}

is_lab() { $NFT list table inet outlock >/dev/null 2>&1; }

test_connect() {
	echo -n "Github: "; curl -4sS -o /dev/null -w '%{http_code}\n' https://github.com || true
	echo -n "Google: "; curl -4sS --connect-timeout 5 -o /dev/null -w '%{http_code}' https://google.com || true
}

case "$MODE" in
	on|lab)		apply_lab ;;
	off|normal) 	apply_normal ;;
	update) 	populate_gh ;;
	toggle) 	is_lab && apply_lab || apply_normal ;; #switch on/off
	status) 	is_lab && echo "mode: LAB" || echo "mode: NORMAL" ;;
	test) 		test_connect ;; 
	auto) 		curl -4sSfI https://github.com >/dev/null && apply_lab ||apply_normal ;;
	*) echo "Usage: $0 {on|off|toggle|update|status|test|auto}"; exit 1 ;;
esac
