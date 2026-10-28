#!/usr/bin/env bash
# credscheck.sh - scans TCP ports for selected protocols with Nmap, then runs NetExec (nxc)
# Usage: ./credscheck.sh -t <target> [-u user -p pass] [--protocols smb,ssh] [-o log]
# Options: -t/--target, -u/--user, -p/--pass, -m/--max-attempts,
# --delay-min, --delay-max, --protocols, -o/--output, -y/--yes,
# --timeout, --no-launch, --mask, -h/--help
# Use only on your own infrastructure or with the owner's permission.
# Primarily intended for HTB labs / your own testing.

set -u
set -o pipefail

# Ensure standard system and user binary paths are in PATH
export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin:$HOME/.local/bin"

# ANSI colors — automatically disabled when stdout is not a terminal
if [[ -t 1 ]]; then
	C_RESET='\033[0m'
	C_BOLD='\033[1m'
	C_RED='\033[1;31m'
	C_GREEN='\033[1;32m'
	C_YELLOW='\033[93m' # bright yellow (SGR 93), intentionally not bold (\033[1;33m) for a clearer, more vibrant hue
	C_CYAN='\033[1;36m'
	C_WHITE='\033[1;37m'
	C_DIM='\033[2m'
else
	C_RESET='' C_BOLD='' C_RED='' C_GREEN='' C_YELLOW=''
	C_CYAN='' C_WHITE='' C_DIM=''
fi

target="" user="" pass="" user_set=0 pass_set=0
max_attempts=15 delay_min=0 delay_max=0.3 protocols_arg="" output_file=""
auto_yes=0 no_mask=1 no_launch=0 nxc_timeout=45

help() {
	cat <<'HELP'
credscheck.sh - first checks TCP ports with Nmap, then runs nxc only for
protocols whose assigned port was found OPEN.

-t, --target        target IP/host (required)
-u, --user          username
-p, --pass          password (can be empty: -p "")
-m, --max-attempts  max number of nxc calls (default 15)
--delay-min         minimum delay in seconds (default 0)
--delay-max         maximum delay in seconds (default 0.3)
--protocols         comma-separated protocols
-o, --output        log file
-y, --yes           skip confirmation when the limit is exceeded
--timeout SEC       timeout for a single nxc call in seconds (default 45)
-n, --no-launch     don't ask to launch an interactive client at the end
--mask              mask passwords in the log/terminal (DISABLED by default -
                    passwords are shown in plain text; use this flag before
                    sharing the log with anyone else or uploading it anywhere
                    outside your own disk)
-h, --help          show help

Note: the interactive NFS client flow runs 'sudo mount'/'sudo umount' to mount
      a discovered export — expect a sudo password prompt at that point.

Examples:
  ./credscheck.sh -t 10.10.11.123
  ./credscheck.sh -t 10.10.11.123 -u admin -p 'P@ssw0rd!'
  ./credscheck.sh -t 10.10.11.123 --protocols smb,ssh,ftp --timeout 30 -n
HELP
}

need_value() {
	# $1 = flag name, $2 = $# from call site (ensures argument was provided, allows empty string like -p "")
	if (($2 < 2)); then
		echo "Error: $1 requires a value." >&2
		exit 1
	fi
}
while (($#)); do
	case "$1" in
	-t | --target)
		need_value "$1" $#
		target="$2"
		shift 2
		;;
	-u | --user)
		need_value "$1" $#
		user="$2"
		user_set=1
		shift 2
		;;
	-p | --pass)
		need_value "$1" $#
		pass="$2"
		pass_set=1
		shift 2
		;;
	-m | --max-attempts)
		need_value "$1" $#
		max_attempts="$2"
		shift 2
		;;
	--delay-min)
		need_value "$1" $#
		delay_min="$2"
		shift 2
		;;
	--delay-max)
		need_value "$1" $#
		delay_max="$2"
		shift 2
		;;
	--protocols)
		need_value "$1" $#
		protocols_arg="$2"
		shift 2
		;;
	-o | --output)
		need_value "$1" $#
		output_file="$2"
		shift 2
		;;
	--timeout)
		need_value "$1" $#
		nxc_timeout="$2"
		shift 2
		;;
	-y | --yes)
		auto_yes=1
		shift
		;;
	-n | --no-launch)
		no_launch=1
		shift
		;;
	--mask)
		no_mask=0
		shift
		;;
	-h | --help)
		help
		exit 0
		;;
	*)
		echo "Unknown option: $1 (use --help)." >&2
		exit 1
		;;
	esac
done
[[ -n "$target" ]] || {
	echo "Error: -t/--target is required." >&2
	exit 1
}
[[ "$max_attempts" =~ ^[0-9]+ ]] && ((10#$max_attempts >= 1)) || {
	echo "Error: --max-attempts must be >= 1." >&2
	exit 1
}
max_attempts=$((10#$max_attempts))
[[ "$nxc_timeout" =~ ^[0-9]+ ]] && ((10#$nxc_timeout >= 5)) || {
	echo "Error: --timeout must be a number >= 5." >&2
	exit 1
}
nxc_timeout=$((10#$nxc_timeout))
valid_num() { [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]]; }
valid_num "$delay_min" && valid_num "$delay_max" || {
	echo "Error: delays must be non-negative numbers." >&2
	exit 1
}
awk -v a="$delay_min" -v b="$delay_max" 'BEGIN{exit !(a<=b)}' || {
	echo "Error: delay-min > delay-max." >&2
	exit 1
}
((user_set == pass_set)) || {
	echo "Error: provide both -u and -p, or neither." >&2
	exit 1
}

if [[ -n "$protocols_arg" ]]; then
	IFS=',' read -r -a protocols <<<"$protocols_arg"
	for i in "${!protocols[@]}"; do
		protocols[$i]="${protocols[$i]//[[:space:]]/}"
		protocols[$i]="${protocols[$i],,}"
		[[ -n "${protocols[$i]}" ]] || {
			echo "Error: empty protocol name." >&2
			exit 1
		}
	done
else
	protocols=(smb ssh ftp winrm mssql rdp ldap wmi nfs vnc)
fi

# Common TCP ports. OPEN is only a preliminary filter, not proof the actual protocol is running.
declare -A proto_ports=(
	[smb]="445" [ssh]="22" [ftp]="21" [winrm]="5985,5986"
	[mssql]="1433" [rdp]="3389" [ldap]="389,636,3268,3269"
	[wmi]="135,139,445" [nfs]="111,2049" [vnc]="5900-5903"
)
declare -A port_set=()
for proto in "${protocols[@]}"; do
	[[ -n "${proto_ports[$proto]+x}" ]] || {
		echo "Error: unsupported protocol '$proto'. Allowed: ${!proto_ports[*]}" >&2
		exit 1
	}
	IFS=',' read -r -a pp <<<"${proto_ports[$proto]}"
	for port in "${pp[@]}"; do port_set["$port"]=1; done
done
port_list="$(printf '%s\n' "${!port_set[@]}" | sort -n | paste -sd, -)"

command -v nmap >/dev/null 2>&1 || {
	echo "Error: nmap not found in PATH." >&2
	exit 1
}
command -v nxc >/dev/null 2>&1 || {
	echo "Error: nxc not found in PATH." >&2
	exit 1
}
if [[ -n "$output_file" ]]; then
	: >"$output_file" 2>/dev/null || {
		echo "Error: cannot write log file: $output_file" >&2
		exit 1
	}
fi

strip_ansi() { sed 's/\x1b\[[0-9;]*m//g' <<<"$1"; }
# %b is intentionally used below so embedded ANSI escape sequences (colors/formatting)
# are interpreted when printing to the terminal.
log() {
	printf '%b\n' "$1"
	[[ -n "$output_file" ]] && printf '%s\n' "$(strip_ansi "$1")" >>"$output_file"
}
clog() {
	printf '%b\n' "${1}${2}${C_RESET}"
	[[ -n "$output_file" ]] && printf '%s\n' "$(strip_ansi "$2")" >>"$output_file"
}
# Prefix helpers — one consistent visual language throughout the script
_info()  { clog "$C_CYAN"   "[info]  $*"; }
_warn()  { clog "$C_YELLOW" "[warn]  $*"; }
_err()   { clog "$C_RED"    "[err]   $*"; }
_ok()    { clog "$C_GREEN"  "[ok]    $*"; }

# Startup banner — only show on an interactive terminal, never in redirected output/logs.
show_banner() {
	[[ -t 1 ]] || return 0
	printf '\n%b' "$C_CYAN"
	if command -v figlet >/dev/null 2>&1; then
		figlet -f slant "CREDSCHECK" 2>/dev/null || figlet "CREDSCHECK"
	else
		printf '%b\n' "${C_BOLD}=== CREDSCHECK ===${C_RESET}${C_CYAN}"
	fi
	printf '%b\n' "$C_RESET"
	printf '%b\n\n' "${C_DIM}Nmap TCP scan  |  NetExec checks${C_RESET}"
}

show_banner
_info "Nmap is checking TCP ports: $port_list"
_info "Target: $target"
scan_tmp="$(mktemp)" || exit 1
trap 'rm -f "$scan_tmp"' EXIT
nmap -n -Pn -sT -T4 --max-retries 1 --host-timeout 15s --open -p "$port_list" -oG - "$target" >"$scan_tmp" 2>&1
nmap_rc=$?
if ((nmap_rc != 0)); then
	printf '%b\n' "${C_RED}[err]   Nmap error (code $nmap_rc):${C_RESET}" >&2
	cat "$scan_tmp" >&2
	exit 1
fi

open_ports=""
while IFS= read -r line; do
	[[ "$line" == *"Ports:"* ]] || continue
	field="${line#*Ports: }"
	IFS=',' read -r -a entries <<<"$field"
	for entry in "${entries[@]}"; do
		if [[ "$entry" =~ ^[[:space:]]*([0-9]+)/open/tcp/ ]]; then
			port="${BASH_REMATCH[1]}"
			[[ ",$open_ports," == *,$port,* ]] || open_ports+="${open_ports:+,}$port"
		fi
	done
done <"$scan_tmp"
if [[ -z "$open_ports" ]]; then
	_warn "No open ports detected from the selected list. Not running nxc."
	[[ -n "$output_file" ]] && printf 'Target: %s\nScanned ports: %s\nResult: no OPEN ports\n' "$target" "$port_list" >>"$output_file"
	exit 0
fi
_ok "Open TCP ports: $open_ports"

declare -a active_protocols=()
for proto in "${protocols[@]}"; do
	found=0
	IFS=',' read -r -a pp <<<"${proto_ports[$proto]}"
	for port in "${pp[@]}"; do
		if [[ "$port" == *-* ]]; then
			lo=$((10#${port%-*}))
			hi=$((10#${port#*-}))
			for n in $(seq "$lo" "$hi"); do
				[[ ",$open_ports," == *,$n,* ]] && found=1
			done
		else
			[[ ",$open_ports," == *,$port,* ]] && found=1
		fi
	done
	if ((found)); then
		active_protocols+=("$proto")
	fi
done
((${#active_protocols[@]})) || {
	_warn "Nothing to check."
	exit 0
}
protocols=("${active_protocols[@]}")

# Protocols where anonymous/guest/empty make no protocol-level sense
# (SSH/WinRM/RDP/WMI require a real account; NFS uses export ACLs and RPC UID/GID rather
# than password authentication). In blind mode they only get a single availability
# probe instead of the full list of 5 attempts.
declare -A blind_minimal=([ssh]=1 [winrm]=1 [rdp]=1 [nfs]=1 [wmi]=1)

# Additional, commonly known default vendor/installer credentials - deliberately
# ONLY for mssql (SQL Server auth rarely has a lockout policy). I'm intentionally
# skipping SMB/WinRM/RDP - accounts there usually live in Active Directory with
# a lockout policy, and guessing "admin:admin" carries a real risk of locking
# someone's account out, not just a technical failed attempt.
declare -A extra_defaults=([mssql]="sa:sa sa: sa:Password123 sa:admin")

if ((user_set)); then
	mode="Test of supplied credentials"
else
	mode="Test anonymous/guest/empty (SSH/WinRM/RDP/NFS/WMI: availability probe only)"
fi

get_creds_for_proto() {
	local proto="$1"
	if ((user_set)); then
		proto_users=("$user")
		proto_passwords=("$pass")
	elif [[ -n "${blind_minimal[$proto]:-}" ]]; then
		proto_users=("")
		proto_passwords=("")
	else
		proto_users=(anonymous anonymous "" guest guest)
		proto_passwords=(anonymous "" "" guest "")
		if [[ -n "${extra_defaults[$proto]:-}" ]]; then
			local pair u2 p2
			for pair in ${extra_defaults[$proto]}; do
				IFS=':' read -r u2 p2 <<<"$pair"
				proto_users+=("$u2")
				proto_passwords+=("$p2")
			done
		fi
	fi
}

planned=0
for proto in "${protocols[@]}"; do
	get_creds_for_proto "$proto"
	planned=$((planned + ${#proto_users[@]}))
done
run_count=$planned
if ((planned > max_attempts)); then
	_info "Plan after filtering: $planned nxc calls; limit: $max_attempts."
	if ((auto_yes == 0)); then
		read -r -p "Continue with the limit? [y/N]: " confirm
		[[ "$confirm" =~ ^[Yy] ]] || {
			echo "Aborted."
			exit 1
		}
	fi
	run_count=$max_attempts
fi

mask_pass() {
	local p="$1"
	if [[ -z "$p" ]]; then printf '(empty)'; else printf '%*s' "${#p}" '' | tr ' ' '*'; fi
}

# Sorts an array (via nameref) in descending order by string length - pure bash,
# no piping through external tools (safe even for secrets containing spaces or
# special characters). Needed so masking a shorter password (e.g. "pass")
# doesn't corrupt a fragment of a longer password (e.g. "password").
sort_by_length_desc() {
	local -n arr_ref=$1
	local i j tmp n=${#arr_ref[@]}
	for ((i = 1; i < n; i++)); do
		tmp="${arr_ref[i]}"
		j=$((i - 1))
		while ((j >= 0)) && ((${#arr_ref[j]} < ${#tmp})); do
			arr_ref[j + 1]="${arr_ref[j]}"
			j=$((j - 1))
		done
		arr_ref[j + 1]="$tmp"
	done
}
literal_replace() {
	local text="$1" needle="$2" replacement="$3" before rest
	[[ -z "$needle" ]] && {
		printf '%s' "$text"
		return
	}
	while [[ "$text" == *"$needle"* ]]; do
		before="${text%%"$needle"*}"
		printf '%s%s' "$before" "$replacement"
		rest="${text#*"$needle"}"
		text="$rest"
	done
	printf '%s' "$text"
}

# Display-only symbol per status (never written into the "status" variable
# itself - that string is matched verbatim in several places, e.g. the menu
# and the launch-eligibility filters, so it must stay exactly "SUCCESS" etc.)
# Gives a non-color cue too, so results stay distinguishable for red/green
# colorblind users and in plain-text logs.
status_symbol() {
	case "$1" in
	SUCCESS) printf '%s' '✔' ;;
	"POSSIBLE SUCCESS") printf '%s' '⚠' ;;
	REJECTED) printf '%s' '✗' ;;
	UNKNOWN) printf '%s' '?' ;;
	TIMEOUT | "CONNECTION FAILED" | "NXC ERROR") printf '%s' '!' ;;
	*) printf '%s' ' ' ;;
	esac
}

# Runs "$@" in the background, capturing its stdout+stderr to out_file and its
# exit code to rc_file. On a real terminal it animates a spinner + a live
# elapsed-seconds counter on the current line while waiting, using the caller's
# attempt_tag/proto/creds_display/probe_note variables (intentionally not
# "local" here - bash functions see the caller's scope, and that's what we
# want: a visible, continuously updating progress indicator, instead of a
# single static line that sits unchanged for the whole call and is easy to
# miss, especially on non-TTY output where it wasn't shown at all before.
run_timed() {
	local out_file="$1" rc_file="$2"
	shift 2
	("$@" >"$out_file" 2>&1
	echo $? >"$rc_file") &
	local bg_pid=$! spin='|/-\' i=0 now el ch disp
	if [[ -t 1 ]]; then
		while kill -0 "$bg_pid" 2>/dev/null; do
			now=$EPOCHREALTIME
			el=$(awk -v s="$_t_start" -v n="$now" 'BEGIN{printf "%.0f", n-s}')
			ch="${spin:i++%${#spin}:1}"
			disp="$creds_display"
			((${#disp} > 40)) && disp="${disp:0:37}..."
			printf '\r\033[K%b' "${C_DIM}${attempt_tag} ${proto}  ${disp} ${ch} ${el}s${probe_note}${C_RESET}"
			sleep 0.15
		done
	fi
	wait "$bg_pid"
}

log "${C_CYAN}Mode:     ${C_RESET}$mode"
log "${C_CYAN}Target:   ${C_RESET}$target"
log "${C_CYAN}Ports:    ${C_RESET}$open_ports"
log "${C_CYAN}Protocols:${C_RESET} ${protocols[*]}"
log "${C_CYAN}Calls:    ${C_RESET}$run_count of $planned  (timeout ${nxc_timeout}s, delay ${delay_min}-${delay_max}s)"
if [[ -n "$output_file" ]]; then
	if ((no_mask)); then
		log "${C_CYAN}Log:      ${C_RESET}$output_file ${C_YELLOW}(passwords in PLAIN TEXT - use --mask if this file might end up anywhere else)${C_RESET}"
	else
		log "${C_CYAN}Log:      ${C_RESET}$output_file (passwords masked)"
	fi
fi
log ""

# Use ASCII unit separator (0x1f) as row field delimiter — safe against any
# printable content in proto, creds, status or info fields (including '|').
FS=$'\x1f'

declare -a rows=()
declare -a raw_protos=()
declare -a raw_users=()
declare -a raw_passes=()
declare -a raw_statuses=()
declare -a raw_infos=()

attempt=0
for proto in "${protocols[@]}"; do
	get_creds_for_proto "$proto"
	for idx in "${!proto_users[@]}"; do
		((attempt < run_count)) || break
		u="${proto_users[$idx]}"
		p="${proto_passwords[$idx]}"
		# BUG FIX: use explicit [[ -z ]] instead of :- so that a literal
		# "(empty)" password is not confused with an actual empty string.
		if ((no_mask)); then
			[[ -z "$p" ]] && pm="(empty)" || pm="$p"
		else
			pm="$(mask_pass "$p")"
		fi
		attempt=$((attempt + 1))
		probe_note=""
		((user_set == 0)) && [[ -n "${blind_minimal[$proto]:-}" ]] && probe_note=" ${C_DIM}(availability probe)${C_RESET}"

		# Print a "in progress" line, then hand off to run_timed(): on a real
		# terminal it animates a spinner + live elapsed-seconds counter on this
		# same line for the whole duration of the call (instead of a single
		# static line printed once and left unchanged until the call returns,
		# which is easy to miss and looked identical to "nothing is happening").
		# In redirected/non-TTY output there's no animation to show, so we keep
		# the plain header line there as before.
		creds_display="${u:-<empty>}:${pm}"
		tag_w=${#run_count}
		((tag_w < 2)) && tag_w=2
		attempt_tag="$(printf '[%0*d/%0*d]' "$tag_w" "$attempt" "$tag_w" "$run_count")"
		if [[ ! -t 1 ]]; then
			log "${C_BOLD}${C_WHITE}${attempt_tag} $proto -- ${creds_display}${probe_note}${C_RESET}"
		fi

		_t_start=$EPOCHREALTIME
		_out_file="$(mktemp)" && _rc_file="$(mktemp)" || exit 1
		# NFS isn't password-authenticated (export ACLs / RPC UID-GID instead), and
		# nxc's nfs module adds nothing showmount doesn't already tell us better -
		# so for nfs we skip nxc entirely and call showmount directly. This saves
		# one call and one dead table row compared to running nxc just to discard
		# its output.
		if [[ "$proto" == "nfs" ]]; then
			if command -v showmount >/dev/null 2>&1; then
				run_timed "$_out_file" "$_rc_file" timeout 5s showmount -e "$target"
			else
				: >"$_out_file"
				echo 127 >"$_rc_file"
			fi
		else
			# timeout protects against hanging connections (especially HTB VPN / slow network)
			run_timed "$_out_file" "$_rc_file" timeout "${nxc_timeout}s" nxc "$proto" "$target" -u "$u" -p "$p"
		fi
		output="$(cat "$_out_file")"
		rc="$(cat "$_rc_file")"
		rm -f "$_out_file" "$_rc_file"
		elapsed=$(awk -v s="$_t_start" -v e="$EPOCHREALTIME" 'BEGIN{printf "%.1f", e-s}')

		masked="$output"
		if ((no_mask == 0)); then
			mask_targets=()
			for secret in "$p" "${proto_passwords[@]}"; do
				[[ -z "$secret" ]] && continue
				already=0
				for seen in "${mask_targets[@]:-}"; do [[ "$seen" == "$secret" ]] && {
					already=1
					break
				}; done
				((already)) || mask_targets+=("$secret")
			done
			sort_by_length_desc mask_targets
			for secret in "${mask_targets[@]}"; do masked="$(literal_replace "$masked" "$secret" "$(mask_pass "$secret")")"; done
		fi

		status="UNKNOWN"
		info_field=""
		if [[ "$proto" == "nfs" ]]; then
			if ((rc == 127)); then
				status="NXC ERROR"
				info_field="showmount not found in PATH"
			elif ((rc == 124)); then
				status="TIMEOUT"
				info_field="exceeded 5s"
			elif ((rc != 0)); then
				status="CONNECTION FAILED"
				info_field="showmount failed (code $rc)"
			else
				# Single pass per value instead of parsing the same showmount
				# output twice via separate head/wc pipelines.
				_sm_first=$(awk '$1 ~ /^\// {print $1; exit}' <<<"$output")
				_sm_count=$(awk '$1 ~ /^\// {n++} END{print n+0}' <<<"$output")
				if [[ -n "$_sm_first" ]]; then
					status="SUCCESS"
					if ((_sm_count > 1)); then
						info_field="exports: $_sm_first (+$((_sm_count - 1)))"
					else
						info_field="export: $_sm_first"
					fi
				else
					status="REJECTED"
					info_field="no exports found"
				fi
			fi
		elif ((rc == 124)); then
			status="TIMEOUT"
			info_field="exceeded ${nxc_timeout}s"
		elif grep -qiE 'connection refused|connection error|timed? ?out|no route to host|network is unreachable|could not connect' <<<"$output"; then
			status="CONNECTION FAILED"
			info_field="$(grep -oiE 'connection refused|connection error|timed? ?out|no route to host|network is unreachable|could not connect' <<<"$output" | head -1)"
		elif ((rc != 0)); then
			status="NXC ERROR"
			info_field="exit code $rc"
		elif [[ "$proto" == "ftp" ]] && grep -qE '\[\+\]' <<<"$output"; then
			status="SUCCESS"
		elif [[ "$proto" == "ssh" ]] && grep -qE '\[\+\]' <<<"$output"; then
			status="SUCCESS"
			if grep -qiE 'Pwn3d!' <<<"$output"; then
				info_field="Pwn3d!"
			elif grep -qiE 'Shell access' <<<"$output"; then
				info_field="Shell access"
			fi
		elif [[ "$proto" == "smb" ]] && grep -qE '\[\+\]' <<<"$output"; then
			status="SUCCESS"
			if grep -qiE 'Pwn3d!' <<<"$output"; then
				info_field="Pwn3d! (admin)"
			elif grep -qiE '\(Guest\)' <<<"$output"; then
				info_field="Guest session"
			else
				info_field="User (non-admin)"
			fi
		elif [[ "$proto" == "wmi" ]]; then
			if grep -qiE '\(Default allow anonymous login\)' <<<"$output"; then
				status="REJECTED"
				info_field="epmap only, access denied"
			elif grep -qiE 'Pwn3d!' <<<"$output"; then
				status="SUCCESS"
				info_field="Pwn3d! (admin)"
			elif grep -qE '\[\+\]' <<<"$output"; then
				status="POSSIBLE SUCCESS"
				info_field="no admin (wmiexec denied)"
			elif grep -qE '\[-\]' <<<"$output"; then
				status="REJECTED"
			fi
		elif [[ "$proto" == "winrm" ]]; then
			# nxc winrm always sets (Pwn3d!) after any successful WSMan enumerate,
			# regardless of actual admin/Remote Management Users membership (nxc bug).
			# Treat every [+] as POSSIBLE SUCCESS — creds are valid but evil-winrm
			# requires the user to be in Remote Management Users or Administrators.
			if grep -qE '\[\+\]' <<<"$output"; then
				status="POSSIBLE SUCCESS"
				info_field="valid creds (needs Remote Management Users)"
			elif grep -qE '\[-\]' <<<"$output"; then
				status="REJECTED"
			fi
		elif grep -qiE '\[\+\].*(Pwn3d!|logged in|login successful|authenticated)' <<<"$output"; then
			status="SUCCESS"
		elif grep -qE '\[\+\]' <<<"$output"; then
			status="POSSIBLE SUCCESS"
		elif grep -qE '\[-\]' <<<"$output"; then
			status="REJECTED"
		fi

		# Print final one-line result (overwriting the spinner line on a terminal)
		_elapsed_s="${elapsed}s"
		_sym="$(status_symbol "$status")"
		_line_plain="$(printf '%s %-1s %-7s %-22s %-20s %7s' "$attempt_tag" "$_sym" "$proto" "$creds_display" "$status" "$_elapsed_s")"
		case "$status" in
		SUCCESS)
			_color="$C_GREEN"
			;;
		"POSSIBLE SUCCESS")
			_color="$C_YELLOW"
			;;
		REJECTED)
			_color="$C_RED"
			;;
		TIMEOUT | "CONNECTION FAILED" | "NXC ERROR")
			_color="$C_YELLOW"
			;;
		*)
			_color=""
			;;
		esac
		if [[ -t 1 ]]; then
			printf '\r\033[K%b\n' "${_color}${_line_plain}${C_RESET}"
			[[ -n "$output_file" ]] && printf '%s\n' "$_line_plain" >>"$output_file"
		else
			log "${_color}${_line_plain}${C_RESET}"
		fi

		# Verbose nxc output goes to log file only; on terminal it is suppressed
		# to keep output clean. To see raw nxc output redirect with -o.
		if [[ -n "$output_file" ]]; then
			printf '%s\n\n' "$(strip_ansi "$masked")" >>"$output_file"
		fi

		rows+=("${proto}${FS}${creds_display}${FS}${status}${FS}${_elapsed_s}${FS}${info_field}")

		raw_protos+=("$proto")
		raw_users+=("$u")
		raw_passes+=("$p")
		raw_statuses+=("$status")
		raw_infos+=("$info_field")

		if ((user_set == 0)) && [[ "$status" == "SUCCESS" ]]; then
			if ((idx + 1 < ${#proto_users[@]})); then
				skipped_for_proto=$(( ${#proto_users[@]} - idx - 1 ))
				_ok "Confirmed success for $proto — skipping $skipped_for_proto remaining blind check(s)."
			fi
			break
		fi

		if ((attempt < run_count)); then
			delay=$(awk -v r="$RANDOM" -v min="$delay_min" -v max="$delay_max" 'BEGIN{srand(r); printf "%.2f", min+rand()*(max-min)}')
			sleep "$delay"
		fi
	done
	((attempt >= run_count)) && break
done
if ((planned > attempt)); then
	log "${C_DIM}Finished in $attempt call(s); skipped $((planned - attempt)) combinations (success detected or limit).${C_RESET}"
fi

# -- SUMMARY ------------------------------------------------------------------
log ""

# Compute column widths first, so the banner line and the separator under the
# header share one real width (previously the banner was a hardcoded 80-dash
# line, independent of the dynamically-sized separator below the header - the
# two could visually disagree depending on how wide the actual data was).
_w_sym=1 _w_proto=5 _w_creds=5 _w_status=6
for row in "${rows[@]}"; do
	IFS="$FS" read -r _p _c _s _e _i <<<"$row"
	(( ${#_p} > _w_proto  )) && _w_proto=${#_p}
	(( ${#_c} > _w_creds  )) && _w_creds=${#_c}
	(( ${#_s} > _w_status )) && _w_status=${#_s}
done
_hdr="$(printf "  %-${_w_sym}s %-${_w_proto}s  %-${_w_creds}s  %-${_w_status}s  %7s  %s" "" PROTO CREDS STATUS TIME INFO)"
_sep_len=${#_hdr}
((_sep_len < 40)) && _sep_len=40

_summary_title="-- SUMMARY "
log "${C_BOLD}${C_CYAN}${_summary_title}$(printf '%0.s-' $(seq 1 $((_sep_len - ${#_summary_title}))))${C_RESET}"
log "${C_BOLD}${C_WHITE}${_hdr}${C_RESET}"
log "${C_DIM}$(printf '%0.s-' $(seq 1 "$_sep_len"))${C_RESET}"

confirmed=0 possible=0 unknown=0 rejected_count=0
for row in "${rows[@]}"; do
	IFS="$FS" read -r _proto _creds _status _elapsed _info <<<"$row"
	_sym="$(status_symbol "$_status")"
	_line="$(printf "  %-${_w_sym}s %-${_w_proto}s  %-${_w_creds}s  %-${_w_status}s  %7s  %s" "$_sym" "$_proto" "$_creds" "$_status" "$_elapsed" "$_info")"
	if [[ "$_status" == "SUCCESS" ]]; then
		log "${C_GREEN}${C_BOLD}${_line}${C_RESET}"
		confirmed=$((confirmed + 1))
	elif [[ "$_status" == "POSSIBLE SUCCESS" ]]; then
		log "${C_YELLOW}${C_BOLD}${_line}${C_RESET}"
		possible=$((possible + 1))
	elif [[ "$_status" == "UNKNOWN" ]]; then
		log "${C_DIM}${_line}${C_RESET}"
		unknown=$((unknown + 1))
	elif [[ "$_status" == "REJECTED" ]]; then
		log "${C_RED}${_line}${C_RESET}"
		rejected_count=$((rejected_count + 1))
	elif [[ "$_status" == "TIMEOUT" ]] || [[ "$_status" == "CONNECTION FAILED" ]] || [[ "$_status" == "NXC ERROR" ]]; then
		log "${C_YELLOW}${_line}${C_RESET}"
	else
		log "$_line"
	fi
done

log "${C_DIM}$(printf '%0.s-' $(seq 1 "$_sep_len"))${C_RESET}"

_total=${#rows[@]}
if ((confirmed > 0)); then
	log "${C_GREEN}${C_BOLD}  ✔  confirmed: $confirmed / $_total${C_RESET}"
else
	log "${C_DIM}  ✔  confirmed: $confirmed / $_total${C_RESET}"
fi
if ((possible > 0)); then
	log "${C_YELLOW}${C_BOLD}  ⚠  possible (nxc [+] hint, unverified): $possible / $_total${C_RESET}"
else
	log "${C_DIM}  ⚠  possible (nxc [+] hint, unverified): $possible / $_total${C_RESET}"
fi
log "${C_DIM}  ?  unknown (nxc output not classified): $unknown / $_total${C_RESET}"
if ((rejected_count > 0)); then
	log "${C_RED}  ✗  rejected:  $rejected_count / $_total${C_RESET}"
else
	log "${C_DIM}  ✗  rejected:  $rejected_count / $_total${C_RESET}"
fi
log ""
log "${C_DIM}[info]  The meaning of \"[+]\" differs between protocols; verify results manually.${C_RESET}"

declare -a valid_indices=()
declare -a non_rejected_indices=()
for i in "${!raw_statuses[@]}"; do
	st="${raw_statuses[$i]}"
	if [[ "$st" == "SUCCESS" ]] || [[ "$st" == "POSSIBLE SUCCESS" ]]; then
		valid_indices+=("$i")
	fi
	if [[ "$st" != "REJECTED" && "$st" != "CONNECTION FAILED" && "$st" != "TIMEOUT" ]]; then
		non_rejected_indices+=("$i")
	fi
done

if (( ${#non_rejected_indices[@]} > 0 && no_launch == 0 )); then
	launch_choice="n"
	if ((${#valid_indices[@]} > 0)); then
		echo ""
		_ok "Matching credentials or potential successes detected!"
		read -r -p "Do you want to launch an external tool and log in to one of the services? [y/N]: " launch_choice
	else
		echo ""
		_warn "No confirmed successes in nxc."
		read -r -p "Do you want to try logging in to one of the checked services anyway (e.g. SSH/SMB/FTP)? [y/N]: " launch_choice
	fi

	if [[ "$launch_choice" =~ ^[Yy] ]]; then
		declare -a current_choices=()
		if ((${#valid_indices[@]} > 0)); then
			current_choices=("${valid_indices[@]}")
		else
			current_choices=("${non_rejected_indices[@]}")
		fi

		choice_idx=""
		while true; do
			echo ""
			clog "$C_CYAN" "Select an entry to connect to:"

			for opt_num in "${!current_choices[@]}"; do
				idx="${current_choices[$opt_num]}"
				p_proto="${raw_protos[$idx]}"
				p_user="${raw_users[$idx]}"
				p_pass="${raw_passes[$idx]}"
				p_stat="${raw_statuses[$idx]}"
				display_u="${p_user:-<empty>}"
				if ((no_mask)); then
					display_p="${p_pass:-<empty>}"
				else
					display_p="$(mask_pass "$p_pass")"
				fi
				p_info="${raw_infos[$idx]:-}"
				if [[ -n "$p_info" ]]; then
					display_stat="$p_stat - $p_info"
				else
					display_stat="$p_stat"
				fi
				printf "  [%d] %s Protocol: %-5s | User: %-12s | Password: %-20s (%s)\n" "$((opt_num + 1))" "$(status_symbol "$p_stat")" "$p_proto" "$display_u" "$display_p" "$display_stat"
			done
			_show_all_available=$((${#current_choices[@]} < ${#non_rejected_indices[@]}))
			if ((_show_all_available)); then
				printf "  [a] Show all checked services (incl. UNKNOWN/NXC ERROR, excl. rejected/failed/timeout)\n"
			fi

			if ((_show_all_available)); then
				read -r -p "Enter option number, [a] for all, or Enter to cancel: " choice_idx
			else
				read -r -p "Enter the option number (or press Enter to cancel): " choice_idx
			fi
			if [[ "$choice_idx" =~ ^[Aa]$ ]] && ((${#current_choices[@]} < ${#non_rejected_indices[@]})); then
				current_choices=("${non_rejected_indices[@]}")
				continue
			fi
			break
		done

		if [[ "$choice_idx" =~ ^[0-9]+ ]] && ((choice_idx >= 1 && choice_idx <= ${#current_choices[@]})); then
			selected_array_idx="${current_choices[$((choice_idx - 1))]}"
			s_proto="${raw_protos[$selected_array_idx]}"
			s_user="${raw_users[$selected_array_idx]}"
			s_pass="${raw_passes[$selected_array_idx]}"
			s_stat="${raw_statuses[$selected_array_idx]}"
			s_info="${raw_infos[$selected_array_idx]:-}"

			echo ""
			_info "Selected: protocol $s_proto for target $target (user: ${s_user:-<empty>})"

			# Interactive client sessions use 'exec' to replace the script process directly,
			# avoiding idle parent shell processes or signal forwarding issues.
			case "$s_proto" in
			rdp)
				if command -v xfreerdp >/dev/null 2>&1; then
					_ok "Launching xfreerdp..."
					# Removed /dynamic-resolution and +clipboard – on virtual machines (e.g. HTB)
					# dynamic scaling of the DVC (disp) channel causes a graphics driver error
					# on Windows and an immediate user session sign-out ("Signing out").
					rdp_args=(/v:"$target" /cert:ignore /f)
					if [[ "$s_user" == *"\\"* ]]; then
						rdp_args+=(/d:"${s_user%%\\*}" /u:"${s_user#*\\}")
					elif [[ -n "$s_user" ]]; then
						rdp_args+=(/u:"$s_user")
					fi
					if [[ -n "$s_pass" ]]; then
						rdp_args+=(/p:"$s_pass")
					fi
					exec xfreerdp "${rdp_args[@]}"
				else
					_err "'xfreerdp' not found in PATH."
					_warn "Install it with:"
					echo "  sudo apt update && sudo apt install -y freerdp2-x11"
				fi
				;;
			ssh)
				# Prefer sshpass (automatic password entry) – speeds up the HTB workflow.
				# Falls back to plain ssh (password entered manually).
				if [[ -n "$s_pass" ]] && command -v sshpass >/dev/null 2>&1; then
					_ok "Launching ssh + sshpass (password supplied automatically)..."
					if [[ -n "$s_user" ]]; then
						exec sshpass -p "$s_pass" ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no "${s_user}@${target}"
					else
						exec sshpass -p "$s_pass" ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password -o PubkeyAuthentication=no "$target"
					fi
				elif command -v ssh >/dev/null 2>&1; then
					if [[ -n "$s_pass" ]]; then
						_warn "Note: 'sshpass' not found - you'll need to type the password manually."
						_warn "To have the password entered automatically, install:"
						echo "  sudo apt update && sudo apt install -y sshpass"
					fi
					_ok "Launching ssh (type the password manually)..."
					if [[ -n "$s_user" ]]; then
						exec ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null "${s_user}@${target}"
					else
						exec ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null "$target"
					fi
				else
					_err "'ssh' not found in PATH."
					_warn "Install: sudo apt install openssh-client"
					if [[ -n "$s_pass" ]]; then
						_warn "Additionally, for automatic password entry: sudo apt install sshpass"
					fi
				fi
				;;
			smb)
				if command -v smbclient >/dev/null 2>&1; then
					_ok "Fetching the share list (smbclient -L)..."
					smb_has_pass_flag=0
					if smbclient --help 2>&1 | grep -q -- '--password'; then
						smb_has_pass_flag=1
						smbclient -L "//$target" -U "$s_user" --password="$s_pass"
					else
						smbclient -L "//$target" -U "$s_user%$s_pass"
					fi

					echo ""
					_info "To enter an interactive SMB session, enter the share name (e.g. Devs, C\$, Users):"
					read -r -p "Share name (or Enter to finish): " smb_share
					smb_share="${smb_share#/}"
					smb_share="${smb_share#\\}"
					if [[ -n "$smb_share" ]]; then
						_ok "Launching an interactive smbclient session for //$target/$smb_share..."
						if ((smb_has_pass_flag)); then
							exec smbclient "//$target/$smb_share" -U "$s_user" --password="$s_pass"
						else
							exec smbclient "//$target/$smb_share" -U "$s_user%$s_pass"
						fi
					fi
				else
					_err "'smbclient' not found in PATH."
					_warn "Install it with:"
					echo "  sudo apt update && sudo apt install -y smbclient"
				fi
				;;
			ftp)
				if ! command -v lftp >/dev/null 2>&1; then
					_err "'lftp' not found in PATH."
					_warn "Install it with: sudo apt update && sudo apt install -y lftp"
				else
					_ok "Launching lftp (auto-login, interactive session)..."
					# lftp configuration:
					# - net:timeout 20: FTP servers (e.g. ProFTPD) perform a reverse DNS lookup on
					#   the client's VPN IP (10.10.x.x), which on HTB labs adds a ~10s delay before
					#   the 220 banner is sent. An earlier 5s timeout caused an immediate
					#   "max-retries exceeded" error.
					# - net:max-retries 2: prevents the session from being cut off by a brief lag.
					# - ftp:fix-pasv-address yes: corrects a bad private IP returned by the server in PASV.
					# - ftp:auto-passive-mode yes: uses PASV by default, falling back to active mode (PORT).
					# - ftp:ssl-allow no: skips unnecessary TLS negotiation attempts for plain FTP.
					lftp_tune="set net:timeout 20; set net:max-retries 2; set net:reconnect-interval-base 2; set ftp:ssl-allow no; set ftp:fix-pasv-address yes; set ftp:auto-passive-mode yes;"
					if [[ -n "$s_user" ]]; then
						if [[ "$s_pass" == *","* ]]; then
							# When the password contains a comma, the -u user,pass switch misparses it.
							# lftp's 'user' command takes separate arguments and handles commas correctly.
							exec lftp -e "${lftp_tune} user \"${s_user//\"/\\\"}\" \"${s_pass//\"/\\\"}\";" "$target"
						else
							exec lftp -u "$s_user","$s_pass" -e "$lftp_tune" "$target"
						fi
					else
						exec lftp -e "$lftp_tune" "$target"
					fi
				fi
				;;
			vnc)
				if command -v vncviewer >/dev/null 2>&1; then
					_ok "Launching vncviewer..."
					# Most vncviewer builds will prompt for the password interactively anyway
					exec vncviewer "$target"
				else
					_err "'vncviewer' not found in PATH."
					_warn "Install it with: sudo apt install tigervnc-viewer"
				fi
				;;
			winrm)
				if command -v evil-winrm >/dev/null 2>&1; then
					if [[ "$s_info" == *"Remote Management Users"* ]]; then
						_warn "Note: evil-winrm requires the account to be in 'Remote Management Users' or 'Administrators'."
						_warn "nxc WinRM check is unreliable — this session may fail with 'Access is denied'."
					fi
					_ok "Launching evil-winrm..."
					if [[ -n "$s_pass" ]]; then
						exec evil-winrm -i "$target" -u "$s_user" -p "$s_pass"
					else
						exec evil-winrm -i "$target" -u "$s_user"
					fi
				else
					_err "'evil-winrm' not found in PATH."
					_warn "Install it with:"
					echo "  sudo apt install evil-winrm"
				fi
				;;
			mssql)
				cmd_mssql=""
				if command -v impacket-mssqlclient >/dev/null 2>&1; then
					cmd_mssql="impacket-mssqlclient"
				elif command -v mssqlclient.py >/dev/null 2>&1; then
					cmd_mssql="mssqlclient.py"
				fi

				if [[ -n "$cmd_mssql" ]]; then
					_ok "Launching $cmd_mssql..."
					if [[ "$s_pass" == *":"* ]]; then
						_warn "Note: password contains ':' - the user:pass@host format may break."
						_warn "Consider doing it manually: $cmd_mssql '$s_user'@$target (and enter the password)"
					fi
					exec "$cmd_mssql" "${s_user}:${s_pass}@${target}"
				else
					_err "Neither 'impacket-mssqlclient' nor 'mssqlclient.py' found in PATH."
					_warn "Install the Impacket package: sudo apt install python3-impacket (or pipx install impacket)"
				fi
				;;
			wmi)
				cmd_wmi=""
				if command -v impacket-wmiexec >/dev/null 2>&1; then
					cmd_wmi="impacket-wmiexec"
				elif command -v wmiexec.py >/dev/null 2>&1; then
					cmd_wmi="wmiexec.py"
				fi

				if [[ -n "$cmd_wmi" ]]; then
					if [[ "$s_stat" != "SUCCESS" ]] || [[ "$s_info" == *"no admin"* ]]; then
						_warn "Note: WMI code execution (wmiexec) requires local Administrator privileges."
						_warn "This account is not confirmed as admin, so wmiexec will likely fail with 'rpc_s_access_denied'."
					fi
					_ok "Launching $cmd_wmi..."
					if [[ -n "$s_pass" ]]; then
						exec "$cmd_wmi" "${s_user}:${s_pass}@${target}"
					else
						exec "$cmd_wmi" "${s_user}@${target}"
					fi
				else
					_err "Neither 'impacket-wmiexec' nor 'wmiexec.py' found in PATH."
					_warn "Install: sudo apt install python3-impacket"
				fi
				;;
			nfs)
				# Note: deliberately not using exec because mount instructions follow below.
				if command -v showmount >/dev/null 2>&1; then
					_ok "Fetching the NFS share list (showmount -e $target)..."
					nfs_out=$(showmount -e "$target" 2>&1)
					nfs_rc=$?
					if ((nfs_rc != 0)); then
						_err "showmount failed (code $nfs_rc):"
						echo "$nfs_out"
					else
						echo "$nfs_out"
						echo ""
						nfs_shares=()
						while IFS= read -r nfs_line; do
							[[ "$nfs_line" =~ ^Export\ list ]] && continue
							nfs_p="$(awk '{print $1}' <<<"$nfs_line")"
							[[ "$nfs_p" =~ ^/ ]] && nfs_shares+=("$nfs_p")
						done <<<"$nfs_out"

						if ((${#nfs_shares[@]} > 0)); then
							_ok "Detected export(s):"
							for s_i in "${!nfs_shares[@]}"; do
								printf "  [%d] %s\n" "$((s_i + 1))" "${nfs_shares[$s_i]}"
							done
							echo ""
							read -r -p "Enter export number to mount and explore (or press Enter to cancel): " nfs_choice
							if [[ "$nfs_choice" =~ ^[0-9]+$ ]] && ((nfs_choice >= 1 && nfs_choice <= ${#nfs_shares[@]})); then
								sel_share="${nfs_shares[$((nfs_choice - 1))]}"
								echo ""
								read -r -p "Local mount directory [/mnt]: " mount_dir
								mount_dir="${mount_dir:-/mnt}"
								if [[ ! -d "$mount_dir" ]]; then
									_info "Directory '$mount_dir' does not exist. Creating with sudo..."
									sudo mkdir -p "$mount_dir"
								fi
								_info "Mounting $target:$sel_share on $mount_dir..."
								if sudo mount -t nfs -o nolock "$target:$sel_share" "$mount_dir" 2>/dev/null || sudo mount -t nfs -o nolock,vers=3 "$target:$sel_share" "$mount_dir"; then
									_ok "Mounted successfully on $mount_dir!"
									echo ""
									_info "Listing contents of $mount_dir:"
									ls -la --color=auto "$mount_dir" 2>/dev/null || ls -la "$mount_dir"
									echo ""
									read -r -p "Open an interactive shell in $mount_dir? [Y/n]: " shell_choice
									if [[ ! "$shell_choice" =~ ^[Nn] ]]; then
										_info "Entering shell in $mount_dir (type 'exit' to return)..."
										(cd "$mount_dir" && bash -i)
									fi
									echo ""
									read -r -p "Do you want to unmount $mount_dir now? [y/N]: " umount_choice
									if [[ "$umount_choice" =~ ^[Yy] ]]; then
										if sudo umount "$mount_dir"; then
											_ok "Unmounted $mount_dir."
										else
											_err "Failed to unmount $mount_dir (files may be in use)."
										fi
									else
										_info "Left mounted at $mount_dir."
									fi
								else
									_err "Failed to mount $target:$sel_share on $mount_dir."
									_info "Manual command: sudo mount -t nfs -o nolock $target:$sel_share $mount_dir"
								fi
							else
								_info "Mount skipped. Manual command:"
								for sh in "${nfs_shares[@]}"; do
									_info "  sudo mount -t nfs -o nolock $target:$sh /mnt"
								done
							fi
						else
							_info "To mount a share:"
							_info "  sudo mount -t nfs -o nolock $target:/SHARE_PATH /mnt"
						fi
					fi
				else
					_err "'showmount' not found in PATH."
					_warn "Install it with: sudo apt install nfs-common"
				fi
				;;
			ldap)
				# Note: deliberately not using exec because follow-up module hints follow below.
				_ok "Querying the domain controller via NetExec LDAP (--users)..."
				timeout "${nxc_timeout}s" nxc ldap "$target" -u "$s_user" -p "$s_pass" --users
				echo ""
				_info "Useful LDAP modules in nxc:"
				_info "  nxc ldap $target -u \"$s_user\" -p \"$s_pass\" --groups"
				_info "  nxc ldap $target -u \"$s_user\" -p \"$s_pass\" --active-users"
				_info "  nxc ldap $target -u \"$s_user\" -p \"$s_pass\" -M laps"
				;;
			*)
				_warn "No predefined interactive client for protocol: $s_proto"
				_info "You can use nxc: nxc $s_proto $target -u \"$s_user\" -p \"$s_pass\""
				;;
			esac
		else
			echo "Cancelled or invalid number selected."
		fi
	fi
fi
