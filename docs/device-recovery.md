# Technician recovery

Technician recovery binds a fresh endpoint credential to an existing logical
Device after clean agent uninstall and reinstall. It preserves the Device UUID,
administrator-managed name, and retained investigation history.

## Distinct enrollment paths

- New enrollment: an unknown key proves possession, receives a short-lived
  pairing code, and an administrator calls `POST /pairings/approve` with the
  code and a workspace-unique `device_name`.
- Ordinary reconnection: a known active credential proves possession and
  resumes contact without technician action.
- Technician recovery: a fresh key proves possession and receives a pairing
  code. An administrator selects the existing Device and calls
  `POST /devices/DEVICE_ID/recover` with that code.

MachineGuid, hostname, hardware serials, copied Device IDs, and installer
material do not authorize recovery. The agent cannot choose the Device it will
replace. Recovery requires administrator authority in the Device's workspace,
the live code bound to a freshly proven key, and explicit Device selection.

## Recovery and naming API

```sh
curl -fsS -X POST \
  -H "Authorization: Bearer $RMM_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"code":"PAIRING_CODE"}' \
  "$RMM_API_URL/devices/$DEVICE_ID/recover"
```

The response reports `awaiting_activation`. Approval consumes the pairing code
but deliberately leaves the previous credential active. The replacement agent
must connect again and prove its fresh nonexportable key. That proof atomically
activates the replacement, records audit evidence attributed to the approving
administrator, and invalidates the previous credential. The old key is denied
thereafter and any old live channel is disconnected.

Device names are non-secret display metadata, unique without regard to case
within a workspace. Administrators can rename a Device with:

```sh
curl -fsS -X PATCH \
  -H "Authorization: Bearer $RMM_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"device_name":"Reception PC"}' \
  "$RMM_API_URL/devices/$DEVICE_ID"
```

Operators cannot approve recovery or rename Devices. Cross-workspace targets
are reported as not found. Revoked Devices, Devices with unresolved live work,
and Devices with a competing pending replacement refuse recovery. An expired
replacement cannot invalidate the current credential.

## Clean reinstall smoke

1. Install and enroll the Windows service with a chosen Device name. Record its
   Device ID and create retained investigation history.
2. Uninstall the MSI. Confirm its service, files, status, and CNG key are gone;
   confirm the server-side Device and history remain.
3. Reinstall and read the fresh pairing code from the protected status file.
4. Call the recovery endpoint for the original Device. Expect
   `awaiting_activation`, not a second Device.
5. Let the service reconnect. Confirm the original Device ID and name are
   online and the earlier history remains readable.
6. Attempt proof with the prior key and expect `denied` without a pairing code.
7. Verify operator, cross-workspace, revoked-Device, retry, and competing-code
   cases cannot create a second active credential.

## Latest validation

On September 22, 2026, the isolated PostgreSQL control-plane suite passed with
the recovery authorization, rotation, concurrent activation, expiry, retained
output, naming, and secret-safe failure cases enabled. Migration downgrade and
re-upgrade also completed against populated recovery data.

The authorized Windows VM/tunnel variables were not available in this worktree,
so the expanded install → enroll → execute → uninstall → reinstall → recover
smoke remains environment-gated and was not run here. Its automated path checks
fresh CNG key creation, unchanged Device ID, and retained output. Because clean
uninstall deletes the nonexportable old private key, that Windows path cannot
replay the deleted key afterward; old-key denial is covered at the real
control-plane WebSocket boundary with an independently held test key. The MSI
is still an unsigned trial artifact and the temporary tunnel remains a
development trust boundary.
