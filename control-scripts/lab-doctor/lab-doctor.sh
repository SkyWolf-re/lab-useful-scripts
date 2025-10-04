#!/usr/bin/env bash
#
#Author: SkyWolf
#Date: 2025-09-14 | Last modified: 2025-10-03
#
#Lab-doctor: pre-flight checks for all lab (constants can be changed for your own lab configuration)
#
VERSION="0.0.3"

set -Euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH

REPORT_DIR="${LABDOCTOR_REPORT_DIR:-/var/log/lab-doctor}"
STAMP="$(date +%Y%m%d-%H%M)"
REPORT_MD="${REPORT_DIR}/lab-doctor-${STAMP}.md"
REPORT_JSON="${REPORT_DIR}/lab-doctor-${STAMP}.json"

#----------------------------------------CLI-Flags-----------------------------------------------------------------
FLAG_FAST=0
FLAG_TOOLS_ONLY=0
FLAG_JSON=0
FLAG_FIX=0

#CLI parsing
usage() {
	cat <<USAGE
lab-doctor ${VERSION}
Usage: lab-doctor [--fast|-f] [-tools-only|-t] [--json|-j] [--fix|-f] ...
	lab-doctor --help
USAGE
}

parse_args() {

	while (( $# )); do
		case "$1" in
			--fast|-f)  FLAG_FAST=1 ;;
			--tools-only|-t) FLAG_TOOLS_ONLY=1 ;;
			--json|-j) FLAG_JSON=1 ;;
			--fix|-f) FLAG_FIX=1 ;;
			--help|-h) usage, exit 0 ;;
			*) warn "Unknown arg: $1"; usage; exit 1 ;;
		esac
		shift
	done
}

#----------------------------------------Results-----------------------------------------------------------------
RESULT_SECTION=()
RESULT_STATUS=()    #PASS|WARN|FAIL|INFO
RESULT_DETAILS=()   #human-friendly 
RESULT_FIX=()       #optional fixes

add_result() {
	RESULT_SECTION+=("$1"); RESULT_STATUS+=("$2"); RESULT_DETAILS+=("$3"); RESULT_FIX+=("${4:-}")
}

#----------------------------------------Misc--------------------------------------------------------------------
run_to() { #<timeout-sec>
	local t="$1"; shift
	timeout --preserve-status "${t}"s "$@" 2>&1 || true
}

csv_contains() { #"4,2,0" "2" -> 0/1 (bash return)
	[[ ",$1," == *",$2,"* ]]
}

ok() { printf "\e[32m[PASS]\e[0m %s\n" "$*"; } 
warn() { printf "\e[33m[WARN]\e[0m %s\n" "$*"; } 
fail() { printf "\e[31m[FAIL]\e[0m %s\n" "$*"; }

detect_lab_user() {
  #this one's tricky, I tried to find the universal way to find the connected user each time, no matter the connection type
  
  #active login session (systemd)
  if command -v loginctl >/dev/null 2>&1; then
    # first active (TTY/ssh/graphical)
    u=$(loginctl list-sessions --no-legend 2>/dev/null \
        | awk '$3=="yes"{print $2}' \
        | grep -v '^root$' | head -n1)
    [ -n "$u" ] && { printf '%s\n' "$u"; return; }
  fi

  #currently logged-in users (ssh/tty)
  u=$(who 2>/dev/null | awk '{print $1}' | grep -v '^root$' | head -n1)
  [ -n "$u" ] && { printf '%s\n' "$u"; return; }

  #most recently logged-in non-root (lastlog)
  if command -v lastlog >/dev/null 2>&1; then
    u=$(lastlog 2>/dev/null \
        | awk 'NR>1 && $0 !~ /Never logged in/ {print $1, $NF}' \
        | grep -v '^root ' | sort -k2,2r | head -n1 | awk '{print $1}')
    [ -n "$u" ] && { printf '%s\n' "$u"; return; }
  fi

  #most recently touched /home directory owner
  u=$(ls -1d /home/* 2>/dev/null \
        | xargs -r -I{} stat -c '%Y %U' {} 2>/dev/null \
        | sort -nr | awk 'NR==1{print $2}')
  [ -n "$u" ] && { printf '%s\n' "$u"; return; }

  #fallback: first non-system user (UID >= 1000) if REALLY nothing has worked
  u=$(getent passwd | awk -F: '$3>=1000 && $1!="nobody"{print $1}' | head -n1)
  printf '%s\n' "${u:-unknown}"
}

#cache to store repeatable sequences to gain time
declare -A CACHE
cache() {
	local k="$1"; shift
	if [[ -z "${CACHE[$k]+x}" ]]; then
		CACHE[$k]="$("$@" 2>/dev/null || true)"
	fi
	printf '%s' "${CACHE[$k]}"
}

grep_once() {
	local pat="$1"; shift
	local n
	n=$(grep -RIE --"$pat" "$@" 2>/dev/null | wc -l)
	[[ "$n" -eq 1 ]]
}

esc_pipes() {
	sed 's/|/\\|/g'
}

#----------------------------------------Checkers-----------------------------------------------------------------
#main meat

check_identity() {

	#Detect virt env
	local virt="unknown" src=""
	if command -v systemd-detect-virt >/dev/null 2>&1; then
		if systemd-detect-virt -q; then
			virt="$(systemd-detect-virt 2>/dev/null)" #expect qemu, kvm, vmare or others
		else
			virt="none"
		fi
		src="systemd-detect-virt"
	elif command-v virt-what >/dev/null 2>&1; then
		virt="$(virt-what 2>/dev/null | tr '\n' '.' | sed 's/,$//')"; [[ -z "$virt" ]] && virt="none"
		src="virt-what"
	else #fallback
		local pn pv
		pn="$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)"
		pv="$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)"
		if grep -qiE 'QEMU|KVM|VMware|VirtualBox|Xen|Hyper-V|Parallels|Bochs' <<< "$pn $pv"; then
			virt="dmi"
		elif grep -qi hypervisor /proc/cpuinfo 2>/dev/null; then
			virt="generic-hypervisor"
		else 
			virt="none"
		fi
		src="dmi"
	fi

	#root warning
	local user_name; user_name="$(detect_lab_user)"
	if [[ "$virt" == "none" ]]; then
		add_result "Identity" "WARN" "Physical machine detected - src=${src} user=${user_name}" \
			"Proceed only if this is an intentional workflow. Run live samples on bare metal only if you fully understand the impact" #or if you're not a bozo
		return
	fi

	if [[ "$EUID" -eq 0 ]]; then
		add_result "Identity" "WARN" "VM detected - ${virt} (src=${src}) | running as root)" \
			"Don't use root if not needed"
	else
		add_result "Identity" "PASS" "VM detected - ${virt} (src=${src} | user=${user_name})"
	fi
}

check_ssh() {
  	
  	local status="PASS"
  	local note=() fix=()

  	#config parses
  	local parse_out
  	parse_out="$(run_to 3 sshd -t)"
  	if [[ -n "$parse_out" ]]; then
		if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
			note+=("config=ok") #checking for false positives
		else
			status="FAIL"
			note+=("config_error=$(printf '%s' "$parse_out" | head -1)")
		fi
	fi
	if ! ls /etc/ssh/ssh_host_*key >/dev/null 2>&1; then
    		status="FAIL"
    		note+=("config_error=$(printf '%s' "$parse_out" | head -1)")
		if grep -qi 'no hostkeys available' <<<"$parse_out"; then
			fix+=("Generate host keys: sudo ssh-keygen -A && sudo systemctl restart ssh")
		else
    			fix+=("Review sshd_config (tip: sshd -t shows first error)")
		fi
	fi

  	#effective port from sshd -T (cached)
  	local T port
  	T="$(cache sshdT sshd -T)"
  	port="$(printf '%s\n' "$T" | awk '/^port /{print $2; exit}')"
  	: "${port:=22}"

  	#service active
  	if systemctl is-active --quiet ssh; then
    		note+=("service=active")
  	else
    		status="FAIL"
    		note+=("service=inactive")
    		fix+=("Enable service: systemctl enable --now ssh")
  	fi

  	#listening on the chosen port
  	if ss -lntp 2>/dev/null | awk '{print $4}' | grep -qE "(^|:)${port}$"; then
    		note+=("listen=:${port}")
  	else
    		status="FAIL"
    		note+=("listen=missing(:${port})")
  	fi

  	#SFTP subsystem exactly once
  	if grep_once '^\s*Subsystem\s\+sftp\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d; then
    		note+=("sftp=ok")
  	else
    		status="WARN"
    		note+=("sftp=missing_or_duplicate")
    		fix+=("Ensure single line: Subsystem sftp /usr/lib/openssh/sftp-server")
  	fi

  	#AllowTcpForwarding (VS Code needs this)
  	if printf '%s\n' "$T" | grep -qi '^allowtcpforwarding yes$'; then
    		note+=("forwarding=yes")
  	else
    		status="WARN"
    		note+=("forwarding=no")
    		fix+=("Set AllowTcpForwarding yes (keep GatewayPorts no)")
  	fi

  	#priv-sep dir
  	if [[ -d /run/sshd ]]; then
    		note+=("privsep=/run/sshd")
  	else
    		status="WARN"
    		note+=("privsep=missing")
    		fix+=("Create via systemd override: RuntimeDirectory=sshd")
  	fi

  	#nft loopback egress (best-effort; needs sudo -n)
  	local rs table chain
 	table="${LAB_NFT_TABLE:-outlock}"
  	chain="${LAB_NFT_OUTPUT_CHAIN:-output}"
  	rs="$(sudo -n nft list ruleset 2>/dev/null || true)"
  	if [[ -n "$rs" ]]; then
    		if printf '%s' "$rs" | grep -A40 -E "table inet ${table}\b" \
       		| grep -A80 -E "chain ${chain}\b" \
       		| grep -qE 'oif\s+lo|daddr\s+127\.0\.0\.1|::1'; then
      			note+=("nft_lo_egress=ok")
    		else
      			status="WARN"
      			note+=("nft_lo_egress=missing")
      			fix+=("Add in ${table}/${chain}: oif lo accept; ip daddr 127.0.0.1 accept; ip6 daddr ::1 accept")
    		fi
  	else
    		note+=("nft_lo_egress=unchecked(no_sudo)")
  	fi

  	#optional host→guest forward hint
  	if [[ -n "${LAB_EXPECTED_HOST_SSH:-}" ]]; then
    		note+=("host_forward=${LAB_EXPECTED_HOST_SSH}->:${port}")
  	fi

	#bBuild details
	details="sshd active & listening on :${port}; $(IFS='; '; echo "${note[*]}")"
	# Sanitize for table
	details="${details//$'\r'/}"
	details="${details//$'\n'/ }"
	details="$(printf '%s' "$details" | sed 's/|/\\|/g' | sed -e 's/  \+/ /g' -e 's/^ *//; s/ *$//')"
	fixes=""
	((${#fix[@]})) && fixes="$(IFS='- '; echo "${fix[*]}")"

	add_result "  SSH   " "$status" "$details" "$fixes"
}

#----------------------------------------Report Writers-----------------------------------------------------------------
write_report_md() {

	mkdir -p "$REPORT_DIR"
	{
		printf "# lab-doctor report - %s\n\n" "$STAMP"
		printf "Version: %s\n" "$VERSION"
		printf "## Summary\n\n"
		printf "| Section  |Status| Details \n|----------|------|\n"
		local i
		for ((i=0; i<${#RESULT_SECTION[@]}; i++)); do
			printf "| %s | %s | %s |\n" "${RESULT_SECTION[$i]}" "${RESULT_STATUS[$i]}" "${RESULT_DETAILS[$i]}"
		done
		printf "\n## Fix now (suggestions)\n\n"
		local anyfix=0
		for ((i=0; i<${#RESULT_SECTION[@]}; i++)); do
			if [[ -n "${RESULT_FIX[$i]}" ]]; then
				anyfix=1
				printf "**%s**: %s\n" "${RESULT_SECTION[$i]}" "${RESULT_FIX[$i]}"
			fi
		done
		(( $anyfix )) || printf "_No automatic fixes suggested_\n"
	} >"$REPORT_MD"
}

#json writer soon


#----------------------------------------EXIT-codes-----------------------------------------------------------------
# 0 OK, 10 identity, 20 hardering, 30 tools, 40+ multiple
# Planned for later in full implementation - now serves as a skeleton. Surely will change later

derive_exit_code() {
	local code=0
	for i in "${!RESULTS_SECTION[@]}"; do
		case "${RESULT_SECTION[$i]}:${RESULT_STATUS[$i]}" in
			Identity:FAIL)	code=$(( code | 10 )) ;;
			#...
		esac
	done
	echo "${code}"
}



#-------Main--------

main(){

	parse_args "$@"
	printf "lab-doctor %s starting\n" "${VERSION}"

	check_identity
	check_ssh
	
	#optional auto-fix later
	
	write_report_md

	for i in "${!RESULT_SECTION[@]}"; do
		case "${RESULT_STATUS[$i]}" in
			PASS) ok "${RESULT_SECTION[$i]} - ${RESULT_DETAILS[$i]}" ;;
			WARN) warn "${RESULT_SECTION[$i]} - ${RESULT_DETAILS[$i]}" ;;
			FAIL) fail "${RESULT_SECTION[$i]} - ${RESULT_DETAILS[$i]}" ;;
			INFO) ok "${RESULT_SECTION[$i]} - ${RESULT_DETAILS[$i]}" ;;
		esac
	done

	local ec
	ec="$(derive_exit_code)"
	if [[ "$ec" -eq 0 ]]; then ok "Verdict: Ready to bang";
	else fail "Verdict: issues detected (exit $ec)";
	fi
	exit "$ec"
}

trap write_report_md EXIT
main "$@"


