#!/usr/bin/env bash
#
#Author: SkyWolf
#Date: 2025-09-14 | Last modified: 2025-11-05
#
#Lab-doctor: pre-flight checks for all lab (constants can be changed for your own lab configuration)
#
VERSION="0.0.5"

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
count_status() {
  # prints: "<pass> <warn> <fail> <info>"
  local p=0 w=0 f=0 n=0 i
  for (( i=0; i<${#RESULT_STATUS[@]}; i++ )); do
    case "${RESULT_STATUS[i]}" in
      PASS) ((p++)) ;;
      WARN) ((w++)) ;;
      FAIL) ((f++)) ;;
      INFO) ((n++)) ;;
    esac
  done
  printf '%d %d %d %d\n' "$p" "$w" "$f" "$n"
}

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

# semver-ish compare: ver_ge A B  -> returns 0 if A >= B
ver_ge() {
  # normalize to "x.y.z" numeric triplets for sort -V
  local a="${1:-0}" b="${2:-0}"
  [[ "$(printf '%s\n%s\n' "$b" "$a" | sort -V | tail -n1)" == "$a" ]]
}

# first token that looks like a version from a banner line
ver_of() {
  local cmd="$1" rx="${2:-[0-9]+([.][0-9A-Za-z-]+)*}"
  command -v "$cmd" >/dev/null 2>&1 || { echo ""; return 1; }
  "$cmd" --version 2>/dev/null | head -n1 | grep -oE "$rx" | head -n1
}

# - appends "name=got" to note[]; if got < min, appends "<min" tag and a fix
# - returns 0 if OK, 1 if outdated, 2 if missing
note_or_need() {
  local name="$1" got="$2" min="$3"
  if [[ -z "$got" ]]; then
    fix+=("$name"); miss+=("$name")
    return 2
  fi
  if ver_ge "$got" "$min"; then
    note+=("$name=$got")
    return 0
  else
    note+=("$name=${got}<${min}")
    fix+=("$name>=$min")
    return 1
  fi
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
		add_result "IDENTITY " "WARN" "Physical machine detected - src=${src} user=${user_name}" \
			"Proceed only if this is an intentional workflow. Run live samples on bare metal only if you fully understand the impact" #or if you're not a bozo
		return
	fi

	if [[ "$EUID" -eq 0 ]]; then
		add_result "IDENTITY " "WARN" "VM detected - ${virt} (src=${src}) | running as root)" \
			"Don't use root if not needed"
	else
		add_result "IDENTITY " "PASS" "VM detected - ${virt} (src=${src} | user=${user_name})"
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

	add_result "  SSH    " "$status" "$details" "$fixes"
}

check_disk() {
	local status="PASS" note=() fix=()

	local warn_pct=${LAB_DISK_WARN_PCT-15}
	local fail_pct=${LAB_DISK_FAIL_PCT-5}
	[[ $warn_pct =~ ^[0-9]+$ ]] || warn_pct=15
	[[ $fail_pct =~ ^[0-9]+$ ]] || fail_pct=5
	(( fail_pct < warn_pct )) || fail_pct=$(( warn_pct > 5 ? warn_pct - 5 : 1 ))

  	#dedup & resolve
  	local -a targets=("/")
	[[ -n "${HOME:-}" ]] && targets+=("$HOME")
	targets+=("/var/log")

	local -a paths=() p r
	for p in "${targets[@]}"; do
		[[ -d "$p" ]] || continue
		r="$(readlink -f -- "$p" 2>/dev/null || printf '%s' "$p")"
		# de-dup
		local seen=0 q
		for q in "${paths[@]}"; do [[ "$q" == "$r" ]] && { seen=1; break; }; done
		(( seen )) || paths+=("$r")
	done
	((${#paths[@]})) || { add_result "$section" "INFO" "no paths to check" ""; return; }

	# Try GNU df fast-path
	local have_gnu=0
	df --version 2>/dev/null | grep -q 'GNU coreutils' && have_gnu=1

	if (( have_gnu )); then
		# One df call; -l = local filesystems only; --output is stable to parse
		# Columns: target size avail pcent (Use%)
		local line tgt size_k avail_k pcent used free_h size_h pct_free
		# shellcheck disable=SC2207
		mapfile -t _df < <(df -Pkl --output=target,size,avail,pcent -- "${paths[@]}" 2>/dev/null | tail -n +2)
		for line in "${_df[@]}"; do
		read -r tgt size_k avail_k pcent _ <<<"$(printf '%s\n' "$line" | tr -s ' ')"
		pcent=${pcent%%%}                    
		pct_free=$((100 - pcent))
		size_h=$(human_kib "$size_k")
		free_h=$(human_kib "$avail_k")

		if (( pct_free <= fail_pct )); then
			status="$(bump_status "$status" "FAIL")"
			note+=("$(basename "$tgt")=${pct_free}%free(${free_h}/${size_h})")
			case "$tgt" in
			/var/log) fix+=("Free logs: sudo journalctl --vacuum-time=7d && sudo journalctl --vacuum-size=100M") ;;
			"$HOME")  fix+=("Review & clean ~/.cache, Downloads (manually)") ;;
			/)       fix+=("Clean apt cache: sudo apt-get clean; remove old kernels; clear /tmp") ;;
			*)       fix+=("Inspect large dirs in $tgt: sudo du -hxd1 $tgt | sort -h | tail") ;;
			esac
		elif (( pct_free <= warn_pct )); then
			status="$(bump_status "$status" "WARN")"
			note+=("$(basename "$tgt")=${pct_free}%free(${free_h}/${size_h})")
			case "$tgt" in
			/var/log) fix+=("Trim logs: sudo journalctl --vacuum-time=14d") ;;
			"$HOME")  fix+=("Review big files in \$HOME") ;;
			/)       fix+=("apt-get clean; review /var/cache and /tmp") ;;
			esac
		fi
		done
	else
		#POSIX fallback
		local fs size_k used_k avail_k usep mnt pct_free free_h size_h
		for p in "${paths[@]}"; do
		read -r fs size_k used_k avail_k usep mnt < <(df -P -k "$p" | awk 'NR==2{print $1,$2,$3,$4,$5,$6}')
		usep=${usep%%%}; pct_free=$((100 - usep))
		size_h=$(human_kib "$size_k"); free_h=$(human_kib "$avail_k")
		if (( pct_free <= fail_pct )); then
			status="$(bump_status "$status" "FAIL")"
			note+=("$(basename "$p")=${pct_free}%free(${free_h}/${size_h})")
		elif (( pct_free <= warn_pct )); then
			status="$(bump_status "$status" "WARN")"
			note+=("$(basename "$p")=${pct_free}%free(${free_h}/${size_h})")
		fi
		done
	fi

	# shorty
	local details
	if ((${#note[@]})); then
		details="low space → $(IFS='; '; echo "${note[*]}")"
	else
		details="all targets healthy (free > ${warn_pct}%)"
	fi

	local fixes=""
	((${#fix[@]})) && fixes="$(IFS='; '; echo "${fix[*]}")"

	add_result "HARDERING" "$status" "$details" "$fixes"
}

check_tools() {
	local status="PASS"
	local note=() fix=() miss=()

	#compilers /build
	local gcc_v clang_v cmake_v meson_v ninja_v
	gcc_v="$(ver_of gcc)"      || miss+=("gcc")
	clang_v="$(ver_of clang)"  || miss+=("clang")
	cmake_v="$(ver_of cmake)"  || miss+=("cmake")
	meson_v="$(ver_of meson)"  || miss+=("meson")
	ninja_v="$(ver_of ninja)"  || miss+=("ninja")

	note_or_need gcc     "$gcc_v"   10    || status="WARN"
	note_or_need clang   "$clang_v" 12    || status="WARN"
	note_or_need cmake   "$cmake_v" 3.20  || status="WARN"
	note_or_need meson   "$meson_v" 0.60  || status="WARN"
	note_or_need ninja   "$ninja_v" 1.10  || status="WARN"

	#debuggers
	local gdb_v lldb_v
	gdb_v="$(ver_of gdb)"      || miss+=("gdb")
	lldb_v="$(ver_of lldb)"    || miss+=("lldb")

	note_or_need gdb     "$gdb_v"   12    || status="WARN"
	note_or_need lldb    "$lldb_v"  12    || status="WARN"

	# Python
	local py_v pip_v
	py_v="$(python3 -V 2>/dev/null | awk '{print $2}')" || true
	pip_v="$(pip3 --version 2>/dev/null | awk '{print $2}')" || true
	note_or_need python3 "$py_v"    3.10  || status="WARN"
	if [[ -n "$pip_v" ]]; then note+=("pip3=$pip_v"); else fix+=("python3-pip"); status="WARN"; fi

	#RE stack
	local rizin_v cutter_p ghidra_p java_v
	rizin_v="$(ver_of rizin)" || true
	cutter_p=$(command -v cutter 2>/dev/null || true)
	ghidra_p=$(command -v ghidraRun 2>/dev/null || echo "${GHIDRA_INSTALL_DIR:-}")
	java_v="$(ver_of java)" || true

	note_or_need rizin   "$rizin_v" 0.6   || status="WARN"
	[[ -n "$cutter_p" ]] && note+=("cutter=ok") || { fix+=("cutter"); status="WARN"; }
	if [[ -n "$ghidra_p" ]]; then
		note+=("ghidra=ok")
		if [[ -n "$java_v" ]]; then
			note_or_need java "$java_v" 17 || status="WARN"
		else
			fix+=("java>=17 for Ghidra"); status="WARN"
		fi
	else
		fix+=("ghidra"); status="WARN"
	fi

	#YARA
	local yara_v
	yara_v="$(ver_of yara)" || true
	note_or_need yara    "$yara_v"  4.0   || status="WARN"

	#networking/perf
	local tcpdump_v tshark_v perf_p bpftrace_v
	tcpdump_v="$(ver_of tcpdump)" || true
	tshark_v="$(ver_of tshark)"   || true
	perf_p=$(command -v perf 2>/dev/null || true)
	bpftrace_v="$(ver_of bpftrace)" || true

	note_or_need tcpdump "$tcpdump_v" 4.9 || status="WARN"
	note_or_need tshark  "$tshark_v" 4.0  || status="WARN"
	[[ -n "$perf_p" ]] && note+=("perf=ok") || { fix+=("linux-tools (perf)"); status="WARN"; }
	note_or_need bpftrace "$bpftrace_v" 0.14 || status="WARN"

	# ---------- status derive ----------
	# If any critical tool missing -> WARN
	if ((${#miss[@]})) || ((${#fix[@]})); then
		[[ "$status" == "PASS" ]] && status="WARN"
	fi

	local details fixes=""
	details="$(IFS=';'; echo "${note[*]}")"
	((${#fix[@]})) && fixes="$(IFS='; '; echo "${fix[*]}")"
	add_result "  TOOLS  " "$status" "$details" "$fixes"
}


#----------------------------------------Report Writers-----------------------------------------------------------------
write_report_md() {

	mkdir -p "$REPORT_DIR"
	{
		printf "# lab-doctor report - %s\n\n" "$STAMP"
		printf "Version: %s\n" "$VERSION"
		printf "## Summary\n\n"
		printf "|  Section  |Status| Details \n|-----------|------|\n"
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
		local pass warn fail info ec
    	read -r pass warn fail info < <(count_status)
    	ec="$(derive_exit_code)"
    	printf "Summary: PASS=%d WARN=%d FAIL=%d (exit %s)\n\n" "$pass" "$warn" "$fail" "$ec"
	} >"$REPORT_MD"
}

#json writer soon


#----------------------------------------EXIT-codes-----------------------------------------------------------------
derive_exit_code() {
  local code=0 cat st i

  for (( i=0; i<${#RESULT_SECTION[@]}; i++ )); do
    st=${RESULT_STATUS[i]}
    cat=${RESULT_SECTION[i]%:*}   

    case "$st" in
      WARN) code=$(( code | 1 )) ;;  # any warning flips bit 0
      FAIL)
        case "$cat" in
          IDENTITY)  code=$(( code | 2 )) ;;
          SSH)       code=$(( code | 4 )) ;;
          HARDENING) code=$(( code | 8 )) ;;
        esac
        ;;
    esac
  done

  printf '%d\n' "$code"
}

#-------Main--------

main(){

	parse_args "$@"
	printf "lab-doctor %s starting\n" "${VERSION}"

	if [[ "${FLAG_TOOLS_ONLY:-0}" -eq 1 ]]; then
    	check_tools
  	else
    	check_identity
    	check_ssh
    	check_disk
    	check_tools                   
  	fi
	
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
	if [[ "$ec" -eq 0 ]]; then
  		ok   "Verdict: Ready to bang"
	fi
	{
  		read -r p w f _ < <(count_status)
  		printf "Summary: PASS=%d WARN=%d FAIL=%d (exit %s)\n" "$p" "$w" "$f" "$ec"
	} >&2
	exit "$ec"
}

trap write_report_md EXIT
main "$@"