#!/usr/bin/env bash
set -Eeuo pipefail

IMAGE_REF="${1:-}"
if [[ ! "$IMAGE_REF" =~ @sha256:[a-f0-9]{64}$ ]]; then
  echo "Usage: $0 IMAGE@sha256:<64 lowercase hex characters>" >&2
  echo "A mutable image tag is not accepted; supply a reviewed immutable image digest." >&2
  exit 2
fi

command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }
docker info >/dev/null
docker info --format '{{json .Runtimes}}' | grep -q '"runsc"' || {
  echo "Docker does not advertise the runsc runtime" >&2
  exit 1
}
command -v runsc >/dev/null || { echo "runsc is required" >&2; exit 2; }

container_id=""
cleanup() {
  if [[ -n "$container_id" ]]; then
    docker rm -f "$container_id" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

container_id="$(docker create \
  --runtime=runsc \
  --network=none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --memory=128m \
  --cpus=0.5 \
  --pids-limit=64 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --user=65532:65532 \
  --entrypoint=/bin/sh \
  "$IMAGE_REF" \
  -c '
    set -eu
    test "$(id -u)" = "65532"
    if touch /sky-high-rootfs-write-test 2>/dev/null; then
      echo "FAIL: root filesystem accepted a write" >&2
      exit 10
    fi
    touch /tmp/sky-high-scratch-test
    test -f /tmp/sky-high-scratch-test
    if wget -T 3 -q -O /dev/null http://1.1.1.1/; then
      echo "FAIL: direct-IP egress succeeded" >&2
      exit 11
    fi
    if wget -T 3 -q -O /dev/null http://example.com/; then
      echo "FAIL: DNS/network egress succeeded" >&2
      exit 12
    fi
    echo "PASS: non-root identity, read-only root, bounded scratch, and no network"
  ')"

config="$(docker inspect --format '{{.HostConfig.Runtime}}|{{.Config.User}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Memory}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}' "$container_id")"
tmpfs_options="$(docker inspect --format '{{index .HostConfig.Tmpfs "/tmp"}}' "$container_id")"
IFS='|' read -r runtime user network readonly memory nano_cpus pids cap_drop security_opt <<< "$config"

[[ "$runtime" == "runsc" ]] || { echo "FAIL: runtime=$runtime" >&2; exit 1; }
[[ "$user" == "65532:65532" ]] || { echo "FAIL: user=$user" >&2; exit 1; }
[[ "$network" == "none" ]] || { echo "FAIL: network=$network" >&2; exit 1; }
[[ "$readonly" == "true" ]] || { echo "FAIL: readonly rootfs=$readonly" >&2; exit 1; }
[[ "$memory" == "134217728" ]] || { echo "FAIL: memory=$memory" >&2; exit 1; }
[[ "$nano_cpus" == "500000000" ]] || { echo "FAIL: nano_cpus=$nano_cpus" >&2; exit 1; }
[[ "$pids" == "64" ]] || { echo "FAIL: pids_limit=$pids" >&2; exit 1; }
[[ "$tmpfs_options" == "rw,noexec,nosuid,size=16m" ]] || {
  echo "FAIL: /tmp tmpfs options=$tmpfs_options" >&2
  exit 1
}
grep -q 'ALL' <<< "$cap_drop" || { echo "FAIL: all capabilities were not dropped: $cap_drop" >&2; exit 1; }
grep -q 'no-new-privileges' <<< "$security_opt" || { echo "FAIL: no-new-privileges missing: $security_opt" >&2; exit 1; }

echo "Verified container policy: runtime=$runtime user=$user network=$network readonly=$readonly memory=$memory nano_cpus=$nano_cpus pids=$pids tmpfs=$tmpfs_options"
docker start --attach "$container_id"
exit_code="$(docker wait "$container_id")"
[[ "$exit_code" == "0" ]] || { echo "FAIL: sandbox process exited with status $exit_code" >&2; exit 1; }
echo "PASS: gVisor sandbox smoke checks completed"
