#!/usr/bin/env bash
# Read-only M0 host preflight. This script never installs packages, changes host
# configuration, launches containers, or executes untrusted workloads.
set -Eeuo pipefail

failures=0
checks=0

pass() {
  checks=$((checks + 1))
  printf 'PASS  %s\n' "$1"
}

fail() {
  checks=$((checks + 1))
  failures=$((failures + 1))
  printf 'FAIL  %s\n' "$1" >&2
}

info() {
  printf 'INFO  %s\n' "$1"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

expected_runtime_owner="${M0_RUNTIME_OWNER:-root}"

inspect_runtime_binary() {
  local path="$1"
  local label="$2"
  local owner mode digest

  if [[ ! -f "$path" || -L "$path" ]]; then
    fail "$label is not a regular non-symlink file: $path"
    return
  fi

  owner="$(stat -c '%U' "$path")"
  mode="$(stat -c '%a' "$path")"
  info "$label path=$path owner=$owner mode=$mode"

  if [[ "$owner" == "$expected_runtime_owner" ]]; then
    pass "$label owner matches expected runtime owner $expected_runtime_owner"
  else
    fail "$label owner mismatch; expected $expected_runtime_owner, detected $owner"
  fi

  if (( (8#$mode & 0022) == 0 )); then
    pass "$label is not group/world writable"
  else
    fail "$label is group/world writable"
  fi

  if [[ -x "$path" ]]; then
    pass "$label is executable"
  else
    fail "$label is not executable"
  fi

  if command_exists sha256sum; then
    digest="$(sha256sum -- "$path" | awk '{print $1}')"
    info "$label sha256=$digest"
  else
    fail 'sha256sum is required for runtime binary integrity inventory'
  fi
}

printf '%s\n' 'Sky High M0 host preflight (read-only)'
printf '%s\n' '======================================'

if [[ ! -r /etc/os-release ]]; then
  fail '/etc/os-release is not readable'
else
  # shellcheck disable=SC1091
  . /etc/os-release
  if [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]]; then
    pass "OS is Ubuntu ${VERSION_ID}"
  else
    fail "Expected Ubuntu 24.04; detected ${PRETTY_NAME:-unknown}"
  fi
fi

arch="$(uname -m)"
if [[ "$arch" == "x86_64" ]]; then
  pass "CPU architecture is x86_64"
else
  fail "Expected x86_64; detected $arch"
fi

kernel_release="$(uname -r)"
kernel="${kernel_release%%-*}"
if [[ "$kernel" =~ ^([0-9]+)\.([0-9]+) ]]; then
  kernel_major="${BASH_REMATCH[1]}"
  kernel_minor="${BASH_REMATCH[2]}"
  if (( kernel_major > 5 || (kernel_major == 5 && kernel_minor >= 6) )); then
    pass "Kernel $kernel meets the Linux 5.6 minimum"
  else
    fail "Kernel $kernel is older than Linux 5.6"
  fi
else
  fail "Could not parse kernel version: $kernel"
fi

if [[ -r /sys/fs/cgroup/cgroup.controllers ]]; then
  pass 'Unified cgroup v2 hierarchy is present'
else
  fail 'Unified cgroup v2 hierarchy is not present'
fi

if command_exists containerd; then
  containerd_version="$(containerd --version 2>&1)"
  info "$containerd_version"
  if [[ "$containerd_version" =~ v2\.3\.[0-9]+ ]]; then
    pass 'containerd is on the 2.3 LTS line'
  else
    fail 'Expected containerd 2.3.x LTS'
  fi

  if [[ -n "${M0_CONTAINERD_CONFIG:-}" ]]; then
    if config_dump="$(containerd --config "$M0_CONTAINERD_CONFIG" config dump 2>/dev/null)"; then
      config_dump_status=0
    else
      config_dump_status=1
    fi
  elif config_dump="$(containerd config dump 2>/dev/null)"; then
    config_dump_status=0
  else
    config_dump_status=1
  fi
  if (( config_dump_status == 0 )); then
    if grep -Eq '^version[[:space:]]*=[[:space:]]*3([[:space:]]|$)' <<<"$config_dump"; then
      pass 'containerd configuration uses version 3'
    else
      fail 'containerd configuration is not version 3'
    fi
    if grep -Fq 'io.containerd.runsc.v1' <<<"$config_dump"; then
      pass 'local containerd config dump contains the gVisor runtime handler'
    else
      fail 'local containerd config dump lacks runtime handler io.containerd.runsc.v1'
    fi
  else
    fail 'containerd config dump failed; inspect daemon configuration'
  fi
else
  fail 'containerd binary is not installed or not on PATH'
fi

if command_exists runsc; then
  runsc_command="$(command -v runsc)"
  runsc_output="$(runsc --version 2>&1)"
  IFS= read -r runsc_version <<<"$runsc_output"
  info "$runsc_version"
  if [[ -n "$runsc_version" ]]; then
    pass 'gVisor runsc binary responds to --version'
  else
    fail 'gVisor runsc returned an empty version'
  fi

  if command_exists readlink; then
    if runsc_path="$(readlink -f "$runsc_command" 2>/dev/null)" && [[ -n "$runsc_path" ]]; then
      inspect_runtime_binary "$runsc_path" 'gVisor runsc'

      # Since the 2026-07 multi-file release transition, runsc requires its
      # adjacent gvisor-bin/ sidecar binaries. Do not rely on legacy
      # best-effort auto-download behavior.
      sidecar_dir="$(dirname "$runsc_path")/gvisor-bin"
      if [[ -d "$sidecar_dir" && ! -L "$sidecar_dir" ]]; then
        sidecar_owner="$(stat -c '%U' "$sidecar_dir")"
        sidecar_mode="$(stat -c '%a' "$sidecar_dir")"
        info "gVisor sidecar directory=$sidecar_dir owner=$sidecar_owner mode=$sidecar_mode"
        if [[ "$sidecar_owner" == "$expected_runtime_owner" ]]; then
          pass 'gVisor sidecar directory owner matches expected runtime owner'
        else
          fail "gVisor sidecar directory owner mismatch; expected $expected_runtime_owner, detected $sidecar_owner"
        fi
        if (( (8#$sidecar_mode & 0022) == 0 )); then
          pass 'gVisor sidecar directory is not group/world writable'
        else
          fail 'gVisor sidecar directory is group/world writable'
        fi

        if [[ -n "$(find "$sidecar_dir" -mindepth 1 -maxdepth 1 -type l -print -quit)" ]]; then
          fail 'gVisor sidecar directory contains a symlink entry'
        else
          pass 'gVisor sidecar directory contains no symlink entries'
        fi

        mapfile -d '' -t sidecar_binaries < <(find "$sidecar_dir" -mindepth 1 -maxdepth 1 -type f -perm /111 -print0)
        if (( ${#sidecar_binaries[@]} > 0 )); then
          pass "gVisor sidecar directory contains ${#sidecar_binaries[@]} executable file(s)"
          for sidecar in "${sidecar_binaries[@]}"; do
            inspect_runtime_binary "$sidecar" "gVisor sidecar $(basename "$sidecar")"
          done
        else
          fail 'gVisor gvisor-bin directory contains no executable sidecar files'
        fi
      else
        fail "gVisor sidecar directory is missing, not a directory, or is a symlink: $sidecar_dir"
      fi
    else
      fail 'Could not resolve the installed runsc binary path'
    fi
  else
    fail 'readlink is required to resolve the installed runsc binary path'
  fi
else
  fail 'gVisor runsc binary is not installed or not on PATH'
fi

if command_exists containerd-shim-runsc-v1; then
  if command_exists readlink; then
    shim_command="$(command -v containerd-shim-runsc-v1)"
    if shim_path="$(readlink -f "$shim_command" 2>/dev/null)" && [[ -n "$shim_path" ]]; then
      inspect_runtime_binary "$shim_path" 'gVisor containerd shim'
    else
      fail 'Could not resolve the installed containerd-shim-runsc-v1 path'
    fi
  else
    fail 'readlink is required to resolve the containerd shim binary path'
  fi
else
  fail 'containerd-shim-runsc-v1 is not installed or not on PATH'
fi

socket="${M0_CONTAINERD_SOCKET:-/run/containerd/containerd.sock}"
expected_socket_owner="${M0_CONTAINERD_SOCKET_OWNER:-root}"
if [[ -S "$socket" ]]; then
  socket_owner="$(stat -c '%U' "$socket")"
  socket_mode="$(stat -c '%a' "$socket")"
  info "containerd socket=$socket owner=$socket_owner mode=$socket_mode"
  if [[ "$socket_owner" == "$expected_socket_owner" ]]; then
    pass "containerd socket owner matches expected principal $expected_socket_owner"
  else
    fail "containerd socket owner mismatch; expected $expected_socket_owner, detected $socket_owner"
  fi
  if (( (8#$socket_mode & 0022) == 0 )); then
    pass 'containerd socket is not group/world writable'
  else
    fail 'containerd socket is group/world writable'
  fi
else
  fail "$socket is missing or is not a Unix socket"
fi

printf '\nChecks: %d; failures: %d\n' "$checks" "$failures"
if (( failures > 0 )); then
  printf '%s\n' 'RESULT: NOT READY — resolve failures; no runtime proof was performed.' >&2
  exit 1
fi

printf '%s\n' 'RESULT: HOST PREFLIGHT PASSED — this is not an isolation or execution approval.'
printf '%s\n' 'Next: run the separately reviewed gVisor smoke and adversarial proof suite on a disposable host.'
