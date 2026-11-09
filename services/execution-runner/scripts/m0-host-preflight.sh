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

  if config_dump="$(containerd config dump 2>/dev/null)"; then
    if grep -Eq '^version[[:space:]]*=[[:space:]]*3([[:space:]]|$)' <<<"$config_dump"; then
      pass 'containerd configuration uses version 3'
    else
      fail 'containerd configuration is not version 3'
    fi
    if grep -Fq 'io.containerd.runsc.v1' <<<"$config_dump"; then
      pass 'gVisor containerd runtime handler is configured'
    else
      fail 'gVisor runtime handler io.containerd.runsc.v1 is not configured'
    fi
  else
    fail 'containerd config dump failed; inspect daemon configuration'
  fi
else
  fail 'containerd binary is not installed or not on PATH'
fi

if command_exists runsc; then
  runsc_output="$(runsc --version 2>&1)"
  IFS= read -r runsc_version <<<"$runsc_output"
  info "$runsc_version"
  if [[ -n "$runsc_version" ]]; then
    pass 'gVisor runsc binary responds to --version'
  else
    fail 'gVisor runsc returned an empty version'
  fi
else
  fail 'gVisor runsc binary is not installed or not on PATH'
fi

if command_exists containerd-shim-runsc-v1; then
  pass 'containerd-shim-runsc-v1 is installed'
else
  fail 'containerd-shim-runsc-v1 is not installed or not on PATH'
fi

socket="/run/containerd/containerd.sock"
if [[ -S "$socket" ]]; then
  socket_owner="$(stat -c '%U' "$socket")"
  socket_mode="$(stat -c '%a' "$socket")"
  info "containerd socket owner=$socket_owner mode=$socket_mode"
  if [[ "$socket_owner" == "root" ]]; then
    pass 'containerd socket is root-owned'
  else
    fail 'containerd socket must be root-owned'
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
