# Device revocation

Device revocation permanently removes a Device's execution authority without
deleting its logical identity, credential history, or investigation history.
Only an authenticated administrator in the device's workspace can revoke it.

## API

```sh
curl -fsS -X POST \
  -H "Authorization: Bearer $RMM_ADMIN_KEY" \
  "$RMM_API_URL/devices/$DEVICE_ID/revoke"
```

The response identifies the device, its durable `revoked` authorization status,
the revocation timestamp and administrator, and whether live session cleanup was
`confirmed`, `unconfirmed`, `not_required`, or had `already_revoked` the device.
Repeating the request is safe and does not create a second revocation.

`GET /devices` reports authorization independently from reachability:

```json
{
  "id": "DEVICE_UUID",
  "authorization_status": "revoked",
  "reachability": "stale",
  "revoked_at": "TIMESTAMP",
  "revoked_by": "CALLER_UUID"
}
```

A recent last heartbeat may briefly leave reachability as `online` after
revocation. This does not confer authority: the durable authorization status is
checked before new sessions or executions, and the control plane tears down the
current endpoint connection.

## Security and cleanup behavior

The control plane commits revocation before attempting remote cleanup. From that
commit onward:

- the old endpoint public key receives `denied` during possession proof;
- the key never returns to pending enrollment and receives no pairing code;
- new debugging sessions return `device_revoked`;
- execution submission through an old session is rejected;
- a connected endpoint is asked to close its current session, then disconnected;
- confirmed endpoint cleanup closes the debugging session normally; and
- unconfirmed work becomes `outcome_unknown` with
  `device_revoked_cleanup_unconfirmed` rather than an invented cancellation.

The one-time pairing code remains only an enrollment approval artifact. The
endpoint's non-exportable private key is its standing credential, and retaining
the revoked public-key record ensures that credential cannot enroll again.

Revocation does not uninstall the endpoint agent, erase its local key, delete
device/session/execution/output history, or revoke caller API credentials. A
revoked Device cannot use technician recovery; unrevocation is unsupported.

## Manual smoke test

1. Pair the Windows endpoint, confirm `authorization_status: active`, and run a
   harmless command.
2. Call `POST /devices/DEVICE_ID/revoke` with the admin credential. Expect
   `authorization_status: revoked`.
3. Confirm a new debugging session returns `409 device_revoked`.
4. Restart the Windows service and wait for a reconnect attempt. The old key must
   receive `denied`; it must not receive a new pairing code.
5. List devices and retrieve prior session/execution output. The device remains
   present with `authorization_status: revoked` and its history remains readable.
6. Repeat the revoke request. Expect `cleanup: already_revoked` with the original
   `revoked_at` and `revoked_by` values.
7. Repeat using an operator credential and an administrator from another
   workspace. Expect `403` and `404`, respectively.
