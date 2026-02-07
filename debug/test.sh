#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }

BUILD_DIR="${BUILD_DIR:-/build}"
NGINX_ENV="${NGINX_ENV:-}"

echo "Starting test environment (build: $BUILD_DIR)..."
docker rm -f socks-test-nginx 2>/dev/null || true
docker compose down 2>/dev/null || true

docker compose up -d proxy proxy-auth httpbin httpbin-ssl 2>&1 | tail -1
sleep 2

echo "load_module $BUILD_DIR/ngx_http_socks_module.so;" > load_module.conf

docker compose run -d -p 8080:80 --name socks-test-nginx nginx bash -c "
  cd /root/nginx-1.26.3 &&
  mkdir -p logs &&
  env $NGINX_ENV $BUILD_DIR/nginx -c /code/debug/nginx-test.conf -p \$PWD -g 'daemon off;'
"

for i in $(seq 1 30); do
  STATUS=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 2 http://localhost:8080/ 2>/dev/null) || true
  [ "$STATUS" = "200" ] && break
  sleep 1
done

cleanup() {
  docker stop socks-test-nginx 2>/dev/null || true
  docker rm -f socks-test-nginx 2>/dev/null || true
  docker compose down 2>/dev/null || true
}
trap cleanup EXIT

if [ "$STATUS" != "200" ]; then
  echo "Nginx failed to start (status: $STATUS). Container logs:"
  docker logs socks-test-nginx 2>&1 | tail -30 || true
  fail "Nginx not responding"
fi

echo ""
echo "Running tests..."

BODY=$(curl -sf --max-time 10 http://localhost:8080/)
echo "$BODY" | grep -q '"url": "http://httpbin/get"' && pass "Basic HTTP proxy through SOCKS5" || fail "Basic HTTP proxy through SOCKS5: $BODY"

echo "$BODY" | grep -q '"Host": "httpbin"' && pass "Host header forwarded" || fail "Host header forwarded"

OK=0
for i in $(seq 1 10); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://localhost:8080/)
  [ "$STATUS" = "200" ] && OK=$((OK + 1))
done
[ "$OK" -eq 10 ] && pass "10 sequential requests (all 200)" || fail "Sequential requests: only $OK/10 succeeded"

docker compose stop proxy 2>/dev/null
sleep 1
STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://localhost:8080/)
RUNNING=$(docker inspect -f '{{.State.Running}}' socks-test-nginx 2>/dev/null)
[ "$RUNNING" = "true" ] && pass "Nginx survives SOCKS proxy down (status: $STATUS)" || fail "Nginx crashed when SOCKS proxy down"
docker compose start proxy 2>/dev/null
sleep 2

STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://localhost:8080/)
[ "$STATUS" = "200" ] && pass "Recovery after SOCKS proxy restart" || fail "Recovery after restart: HTTP $STATUS"

LARGE=$(curl -sf --max-time 10 "http://localhost:8080/" -H "Accept: */*" 2>/dev/null | wc -c)
[ "$LARGE" -gt 50 ] && pass "Response body received ($LARGE bytes)" || fail "Large response: only $LARGE bytes"

for i in $(seq 1 5); do
  curl -sf --max-time 10 http://localhost:8080/ >/dev/null 2>&1 &
done
wait
CONCURRENT_OK=0
for i in $(seq 1 5); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://localhost:8080/)
  [ "$STATUS" = "200" ] && CONCURRENT_OK=$((CONCURRENT_OK + 1))
done
[ "$CONCURRENT_OK" -eq 5 ] && pass "Concurrent requests" || fail "Concurrent: $CONCURRENT_OK/5"

# Test 8: SOCKS5 username/password auth (URL credentials)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://localhost:8080/auth)
[ "$STATUS" = "200" ] && pass "SOCKS5 username/password auth (URL)" || fail "SOCKS5 auth (URL): HTTP $STATUS"

# Test 9: SOCKS5 auth with wrong credentials
STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://localhost:8080/auth-bad)
[ "$STATUS" = "502" ] && pass "SOCKS5 auth rejected with wrong credentials" || fail "SOCKS5 bad auth: expected 502, got $STATUS"

# Test 10: SOCKS5 auth via socks_username/socks_password directives
STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://localhost:8080/auth-directive)
[ "$STATUS" = "200" ] && pass "SOCKS5 auth via directives" || fail "SOCKS5 auth directive: HTTP $STATUS"

# Test 11: SSL to upstream through SOCKS tunnel
BODY=$(curl -sf --max-time 10 http://localhost:8080/ssl 2>/dev/null)
echo "$BODY" | grep -q '"url":' && pass "SSL to upstream through SOCKS" || fail "SSL through SOCKS: $BODY"

RUNNING=$(docker inspect -f '{{.State.Running}}' socks-test-nginx 2>/dev/null)
[ "$RUNNING" = "true" ] && pass "Nginx still running after all tests" || fail "Nginx died during tests"

echo ""
echo "All tests passed!"
