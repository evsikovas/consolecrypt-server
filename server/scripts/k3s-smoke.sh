#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Alexander Evsikov <i@evsikov.net>
#
# Install the Helm chart into a throwaway namespace, run the end-to-end smoke
# test (examples/smoke.rs) through a port-forward, then remove everything.
#
#   server/scripts/k3s-smoke.sh [image-repository] [image-tag]
#
# Defaults to the locally built image `consolecrypt-server:dev` with
# pullPolicy=Never (k3s/OrbStack/kind with access to local images). Uses the
# bundled single-pod PostgreSQL and 2 server replicas (exercises the
# PostgreSQL LISTEN/NOTIFY event fan-out). Touches nothing outside the
# namespace it creates.
set -euo pipefail

REPO="${1:-consolecrypt-server}"
TAG="${2:-dev}"
NS="consolecrypt-smoke-$(date +%s)"
RELEASE=smoke
PORT="${CC_SMOKE_PORT:-18090}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CHART="$HERE/../helm/consolecrypt-server"

cleanup() {
  [[ -n "${PF_PID:-}" ]] && kill "$PF_PID" 2>/dev/null || true
  helm uninstall "$RELEASE" -n "$NS" >/dev/null 2>&1 || true
  kubectl delete namespace "$NS" --wait=true >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "context: $(kubectl config current-context), namespace: $NS, image: $REPO:$TAG"
kubectl create namespace "$NS" >/dev/null
helm install "$RELEASE" "$CHART" -n "$NS" \
  --set postgresql.enabled=true \
  --set replicaCount=2 \
  --set image.repository="$REPO" \
  --set image.tag="$TAG" \
  --set image.pullPolicy="${CC_SMOKE_PULL_POLICY:-Never}" \
  --set config.rateLimit.enabled=false \
  --wait --timeout 300s >/dev/null
kubectl -n "$NS" get pods

kubectl -n "$NS" port-forward "svc/$RELEASE-consolecrypt-server" "$PORT:8080" >/dev/null 2>&1 &
PF_PID=$!
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:$PORT/readyz" >/dev/null 2>&1 && break
  sleep 1
done

(cd "$HERE/.." && cargo run --quiet --example smoke -- "http://127.0.0.1:$PORT")
echo "k3s smoke test passed"
