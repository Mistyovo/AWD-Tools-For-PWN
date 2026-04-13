#!/usr/bin/env bash

COMMON_PWN_TOOLS=(
	python3
	pip3
	gcc
	gdb
	gdb-multiarch
	gdbserver
	checksec
	patchelf
	readelf
	objdump
	strings
	one_gadget
	ROPgadget
	ropper
	pwn
	qemu-x86_64
	qemu-aarch64
	strace
	ltrace
	socat
)

ok_count=0
total_count=0
missing_items=()

C_RESET=""
C_OK=""
C_MISS=""
C_INFO=""
C_TITLE=""
C_WARN=""

enable_color() {
	if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
		C_RESET=$'\033[0m'
		C_OK=$'\033[32m'
		C_MISS=$'\033[31m'
		C_INFO=$'\033[36m'
		C_TITLE=$'\033[1;34m'
		C_WARN=$'\033[33m'
	fi
}

enable_color

check_command() {
	local cmd="$1"
	total_count=$((total_count + 1))

	if command -v "$cmd" >/dev/null 2>&1; then
		local cmd_path
		cmd_path="$(command -v "$cmd")"
		printf "%b[ OK ]%b %-30s %s\n" "$C_OK" "$C_RESET" "$cmd" "$cmd_path"
		ok_count=$((ok_count + 1))
	else
		printf "%b[MISS]%b %-30s -\n" "$C_MISS" "$C_RESET" "$cmd"
		missing_items+=("$cmd")
	fi
}

check_python_module() {
	local module="$1"
	local label="python3 module: $module"
	total_count=$((total_count + 1))

	if command -v python3 >/dev/null 2>&1 && python3 -c "import $module" >/dev/null 2>&1; then
		printf "%b[ OK ]%b %-30s importable\n" "$C_OK" "$C_RESET" "$label"
		ok_count=$((ok_count + 1))
	else
		printf "%b[MISS]%b %-30s -\n" "$C_MISS" "$C_RESET" "$label"
		missing_items+=("$label")
	fi
}

check_gdb_plugin() {
	local plugin="$1"
	local label="gdb plugin: $plugin"
	total_count=$((total_count + 1))

	if [ -f "$HOME/.gdbinit" ] && grep -Eiq "$plugin" "$HOME/.gdbinit"; then
		printf "%b[OK ]%b %-30s loaded in ~/.gdbinit\n" "$C_OK" "$C_RESET" "$label"
		ok_count=$((ok_count + 1))
	else
		printf "%b[MISS]%b %-30s -\n" "$C_MISS" "$C_RESET" "$label"
		missing_items+=("$label")
	fi
}

printf "%b=== PWN Environment Check ===%b\n" "$C_TITLE" "$C_RESET"

if [ "$#" -gt 0 ]; then
	printf "%bMode:%b custom command list\n" "$C_INFO" "$C_RESET"
	for cmd in "$@"; do
		check_command "$cmd"
	done
else
	printf "%bMode:%b common PWN tool list\n" "$C_INFO" "$C_RESET"
	for cmd in "${COMMON_PWN_TOOLS[@]}"; do
		check_command "$cmd"
	done

	echo
	printf "%bExtra checks:%b\n" "$C_INFO" "$C_RESET"
	check_python_module "pwn"
	check_gdb_plugin "pwndbg"
	check_gdb_plugin "gef"
	check_gdb_plugin "peda"
fi

echo
if [ "$ok_count" -eq "$total_count" ]; then
	printf "%bSummary:%b %s/%s installed\n" "$C_OK" "$C_RESET" "$ok_count" "$total_count"
else
	printf "%bSummary:%b %s/%s installed\n" "$C_WARN" "$C_RESET" "$ok_count" "$total_count"
fi

exit 0
