#!/usr/bin/env bash
#
#Author: SkyWolf
#Date: 14-09-2025
#
#Lab-doctor: pre-flight checks for all lab (constants can be changed for your own lab configuration)
#
VERSION="0.0.2"

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
	timeot --preserve-status "${t}"s "$@" 2>&1 || true
}

csv_contains() { #"4,2,0" "2" -> 0/1 (bash return)
	[[ ",$1," == *",$2,"* ]]
}

ok() { printf "\e[32m[PASS]\e[0m %s\n" "$*"; } 
warn() { printf "\e[33m[WARN]\e[0m %s\n" "$*"; } 
fail() { printf "\e[31m[FAIL]\e[0m %s\n" "$*"; } 


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
	local user_name; user_name="$(id -un)"
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


#----------------------------------------Report Writers-----------------------------------------------------------------
write_report_md() {

	mkdir -p "$REPORT_DIR"
	{
		printf "# lab-doctor report - %s\n\n" "$STAMP"
		printf "Version: %s\n" "$VERSION"
		printf "## Summary\n\n"
		printf "| Section  |Status| Details |\n|-----------|------|---|\n"
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


