#!/usr/bin/env bash
# Smoke test for the 27 REST endpoints. Spins up two test users, exercises
# every endpoint, prints a one-line-per-call status table, and cleans up.
#
# Requires: a running server on $BASE (default http://localhost:3001) and a
# reachable Mongo.

set -uo pipefail
BASE="${BASE:-http://localhost:3001}"
PREFIX="${PREFIX:-/api/v1}"
TS=$(date +%s)
ALICE="alice_${TS}"
BOB="bob_${TS}"
PASS="smoke-pass-${TS}"
CALL_ID="CALL-${TS}"

PASS_COUNT=0
FAIL_COUNT=0

log() {
  local status="$1" method="$2" path="$3" expected="$4" got="$5"
  if [[ "$got" == "$expected" || ",$expected,"  == *",$got,"* ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "✓ %-6s %-40s %s (expected %s)\n" "$method" "$path" "$got" "$expected"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf "✗ %-6s %-40s %s (expected %s) [%s]\n" "$method" "$path" "$got" "$expected" "$status"
  fi
}

# Helper: run curl, echo "<status>|<body>"
http() {
  local method="$1" path="$2" body="${3:-}" auth="${4:-}"
  local args=(-sS -o /tmp/smoke.body -w "%{http_code}" -X "$method" "${BASE}${PREFIX}${path}")
  if [[ -n "$body" ]]; then
    args+=(-H 'Content-Type: application/json' -d "$body")
  fi
  if [[ -n "$auth" ]]; then
    args+=(-H "Authorization: Bearer $auth")
  fi
  local code
  code=$(curl "${args[@]}" 2>/dev/null) || code="ERR"
  echo "$code"
}

read_body() { cat /tmp/smoke.body 2>/dev/null; }

KEYBUNDLE='{"publicIdentityKeyX25519":"x25","publicIdentityKeyEd25519":"ed25","publicSignedPreKey":["spk","sig"],"oneTimePreKeys":[{"opkId":"OPK-1","opkPub":"pub-1"}]}'

echo "== Smoke against $BASE$PREFIX (ts=$TS) =="

# 1. Register Alice
code=$(http POST /auth/register "{\"username\":\"$ALICE\",\"password\":\"$PASS\",\"keyBundle\":$KEYBUNDLE}")
log register POST /auth/register 201 "$code"
ALICE_ID=$(node -e "try{const j=JSON.parse(require('fs').readFileSync('/tmp/smoke.body'));process.stdout.write(j.userId||'')}catch(e){}")

# 2. Register Bob
code=$(http POST /auth/register "{\"username\":\"$BOB\",\"password\":\"$PASS\",\"keyBundle\":$KEYBUNDLE}")
log register POST /auth/register 201 "$code"
BOB_ID=$(node -e "try{const j=JSON.parse(require('fs').readFileSync('/tmp/smoke.body'));process.stdout.write(j.userId||'')}catch(e){}")

# 3. Login Alice
code=$(http POST /auth/login "{\"username\":\"$ALICE\",\"password\":\"$PASS\"}")
log login POST /auth/login 200 "$code"
ALICE_TOKEN=$(node -e "try{const j=JSON.parse(require('fs').readFileSync('/tmp/smoke.body'));process.stdout.write(j.token||'')}catch(e){}")

# Need Bob token too (just to confirm independent login)
code=$(http POST /auth/login "{\"username\":\"$BOB\",\"password\":\"$PASS\"}")
log login POST /auth/login 200 "$code"
BOB_TOKEN=$(node -e "try{const j=JSON.parse(require('fs').readFileSync('/tmp/smoke.body'));process.stdout.write(j.token||'')}catch(e){}")

if [[ -z "$ALICE_TOKEN" || -z "$BOB_TOKEN" || -z "$ALICE_ID" || -z "$BOB_ID" ]]; then
  echo "❌ failed to obtain tokens/ids; aborting (alice=$ALICE_ID bob=$BOB_ID)"
  exit 1
fi
echo "alice=$ALICE_ID  bob=$BOB_ID  tokens=ok"

# 4. Search user
code=$(http POST /users/search "{\"searchTerm\":\"$BOB\"}" "$ALICE_TOKEN")
log search POST /users/search 200 "$code"

# 5. Get user
code=$(http GET "/users/$BOB_ID" "" "$ALICE_TOKEN")
log getuser GET /users/:userId 200 "$code"

# 6. Online users
code=$(http GET /users/online "" "$ALICE_TOKEN")
log online GET /users/online 200 "$code"

# 7. Update profile
code=$(http PUT /users/profile/update '{"aboutme":"hello world"}' "$ALICE_TOKEN")
log update PUT /users/profile/update 200 "$code"

# 8. Add friend
code=$(http POST /contacts/add-friend "{\"friendId\":\"$BOB_ID\"}" "$ALICE_TOKEN")
log addfriend POST /contacts/add-friend 200 "$code"

# 9. Remove friend
# Note: the legacy addFriend handler is unilateral while removeFriend requires
# both edges, so a remove right after add can legitimately return 409 not_friends.
# Both 200 and 409 indicate the endpoint is functioning.
code=$(http POST /contacts/remove-friend "{\"friendId\":\"$BOB_ID\"}" "$ALICE_TOKEN")
log rmfriend POST /contacts/remove-friend "200,409" "$code"

# 10. Check messages
code=$(http POST /messages/check "{\"targetUserId\":\"$BOB_ID\"}" "$ALICE_TOKEN")
log check POST /messages/check 200 "$code"

# 11. Latest number
code=$(http POST /messages/latest-number "{\"targetUserId\":\"$BOB_ID\"}" "$ALICE_TOKEN")
log latest POST /messages/latest-number 200 "$code"

# 12. Mark seen
code=$(http POST /messages/mark-seen "{\"targetUserId\":\"$BOB_ID\"}" "$ALICE_TOKEN")
log markseen POST /messages/mark-seen 200 "$code"

# 13. Create group
code=$(http POST /groups/create "{\"name\":\"smoke-grp-$TS\",\"memberIds\":[\"$BOB_ID\"]}" "$ALICE_TOKEN")
log creategrp POST /groups/create "200,201" "$code"
GROUP_ID=$(node -e "try{const j=JSON.parse(require('fs').readFileSync('/tmp/smoke.body'));process.stdout.write(j.group?.groupId||'')}catch(e){}")
echo "group_id=$GROUP_ID"

# 14. List groups
code=$(http GET /groups/list "" "$ALICE_TOKEN")
log listgrp GET /groups/list 200 "$code"

# 15. Get group
code=$(http GET "/groups/$GROUP_ID" "" "$ALICE_TOKEN")
log getgrp GET /groups/:id 200 "$code"

# 16. Add member (bob is already in; expect 409 conflict)
code=$(http POST "/groups/$GROUP_ID/add-member" "{\"memberId\":\"$BOB_ID\"}" "$ALICE_TOKEN")
log addmem POST /groups/:id/add-member "200,409" "$code"

# 17. Remove member
code=$(http POST "/groups/$GROUP_ID/remove-member" "{\"memberId\":\"$BOB_ID\"}" "$ALICE_TOKEN")
log rmmem POST /groups/:id/remove-member 200 "$code"

# 18. Initiate call (target offline expected: 400 target_offline)
code=$(http POST /calls/initiate "{\"targetUserId\":\"$BOB_ID\",\"callId\":\"$CALL_ID\"}" "$ALICE_TOKEN")
log initcall POST /calls/initiate 400 "$code"

# 19/20/21. Accept/Decline/End: call doesn't exist → 404 not_found
code=$(http POST /calls/accept "{\"callId\":\"NOSUCH-$TS\"}" "$ALICE_TOKEN")
log accept POST /calls/accept 404 "$code"
code=$(http POST /calls/decline "{\"callId\":\"NOSUCH-$TS\"}" "$ALICE_TOKEN")
log decline POST /calls/decline 404 "$code"
code=$(http POST /calls/end "{\"callId\":\"NOSUCH-$TS\"}" "$ALICE_TOKEN")
log end POST /calls/end 404 "$code"

# 22. Media-state (bob offline → 400)
code=$(http POST /calls/media-state "{\"targetUserId\":\"$BOB_ID\",\"mediaType\":\"audio\",\"isEnabled\":true}" "$ALICE_TOKEN")
log media POST /calls/media-state 400 "$code"

# 23. Signed prekey
code=$(http POST /keys/signed-prekey "{\"targetUserId\":\"$BOB_ID\"}" "$ALICE_TOKEN")
log spk POST /keys/signed-prekey 200 "$code"

# 24. X25519
code=$(http POST /keys/identity/x25519 "{\"targetUserId\":\"$BOB_ID\"}" "$ALICE_TOKEN")
log x25519 POST /keys/identity/x25519 200 "$code"

# 25. Ed25519
code=$(http POST /keys/identity/ed25519 "{\"targetUserId\":\"$BOB_ID\"}" "$ALICE_TOKEN")
log ed25519 POST /keys/identity/ed25519 200 "$code"

# 26. Bundle
code=$(http POST /keys/bundle "{\"targetUserId\":\"$BOB_ID\"}" "$ALICE_TOKEN")
log bundle POST /keys/bundle 200 "$code"

# 27. OPK upload
code=$(http POST /keys/opk/upload '{"oneTimePreKeys":[{"opkId":"OPK-AB","opkPub":"pubA"},{"opkId":"OPK-CD","opkPub":"pubC"}]}' "$ALICE_TOKEN")
log opkup POST /keys/opk/upload 200 "$code"

# 28. OPK status
code=$(http GET /keys/opk/status "" "$ALICE_TOKEN")
log opkst GET /keys/opk/status 200 "$code"

# Cleanup: delete Alice + Bob (DELETE requires password body)
code=$(http DELETE /users/account/delete "{\"password\":\"$PASS\"}" "$ALICE_TOKEN")
log delA DELETE /users/account/delete 200 "$code"
code=$(http DELETE /users/account/delete "{\"password\":\"$PASS\"}" "$BOB_TOKEN")
log delB DELETE /users/account/delete 200 "$code"

echo ""
echo "== Result: ${PASS_COUNT} passed / ${FAIL_COUNT} failed =="
exit $((FAIL_COUNT > 0 ? 1 : 0))
