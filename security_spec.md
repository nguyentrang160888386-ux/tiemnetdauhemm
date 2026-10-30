# Security Specification (`security_spec.md`)

## 1. Data Invariants

1. **Default-Deny Catch-All**: Any path not explicitly matched is unconditionally denied (`allow read, write: if false;`).
2. **Path Variable Hardening (`isValidId`)**: Every document ID (`{userId}`, `{nickId}`, `{eventId}`) on single-document operations (`get`, `create`, `update`, `delete`) must be a valid string of length 1..128 matching `^[a-zA-Z0-9_\-]+$`.
3. **Save Isolation (`/saves/{userId}`)**:
   - Only a verified authenticated owner (`request.auth.uid == userId && request.auth.token.email_verified == true`) can `get`, `create`, or `update` their own save document.
   - No `list` or `delete` is permitted on `/saves/{userId}`.
   - `blob` must be a string with length `1..900000`, `device` length `<= 120`, `updated_at` length `<= 64`, `day` in `0..100000`, `cash` in `-100000000..100000000000`, and `ts == request.time`.
4. **Leaderboard Integrity (`/players/{userId}`)**:
   - Write access (`create`, `update`) requires verified ownership (`request.auth.uid == userId && request.auth.token.email_verified == true`) and strict validation via `isValidPlayerProfile(incoming())` with `ts == request.time`.
   - Read access (`get`, `list`) enforces query boundaries on `resource.data` (`resource.data.day >= 0 && resource.data.cash >= 0`) and contains no PII (only public game stats and shop name/nickname).
5. **Nickname Ownership (`/nicks/{nickId}`)**:
   - A nickname claim can only be created or updated if `incoming().uid == request.auth.uid` and `isValidNickClaim(incoming())`.
   - On update, `incoming().uid == existing().uid` prevents hijacking an already-claimed nickname belonging to another user.
   - Only the current owner (`existing().uid == request.auth.uid`) can `delete` their old nickname claim.
6. **Telemetry & Master Gate (`/telemetry/{userId}` and `/telemetry/{userId}/events/{eventId}`)**:
   - Supports both authenticated and anonymous sessions (`isSignedIn() && request.auth.uid == userId`).
   - Creating a `/telemetry/{userId}/events/{eventId}` document requires relational consistency (`existsAfter(/databases/$(database)/documents/telemetry/$(userId))` or `exists(/databases/$(database)/documents/telemetry/$(userId))`) and strict schema validation (`isValidTelemetryEvent(incoming())`).

## 2. The "Dirty Dozen" Payloads

1. **Cross-User Save Read (PII/Save Leak)**: User `user_B` attempts `get` on `/saves/user_A`. -> `PERMISSION_DENIED`
2. **Unverified Email Save Write (Email Spoofing)**: User `user_A` with `email_verified: false` attempts `create` on `/saves/user_A`. -> `PERMISSION_DENIED`
3. **Shadow Field Injection on Save (`isAdmin: true`)**: User `user_A` sends a valid `/saves/user_A` payload plus ghost field `isAdmin: true`. -> `PERMISSION_DENIED`
4. **Oversized Blob Denial-of-Wallet (`blob` > 900,000 chars)**: User `user_A` sends a 950KB `blob` to `/saves/user_A`. -> `PERMISSION_DENIED`
5. **Forged Client Timestamp on Save (`ts != request.time`)**: User `user_A` sets `ts` to a past/future timestamp instead of `request.time`. -> `PERMISSION_DENIED`
6. **Cross-User Leaderboard Spoofing**: User `user_B` attempts to write `/players/user_A`. -> `PERMISSION_DENIED`
7. **Value Poisoning on Leaderboard Update**: User `user_A` updates `/players/user_A` with `nick` of length 500 or `cash` as a string. -> `PERMISSION_DENIED`
8. **Nickname Hijacking**: User `user_B` attempts to overwrite `/nicks/pro_gamer` already owned by `user_A`. -> `PERMISSION_DENIED`
9. **Nickname Spoofed UID Creation**: User `user_A` attempts to create `/nicks/test_nick` with `uid: "user_B"`. -> `PERMISSION_DENIED`
10. **Foreign Nickname Deletion**: User `user_B` attempts to delete `/nicks/pro_gamer` owned by `user_A`. -> `PERMISSION_DENIED`
11. **Orphaned Telemetry Event Write**: User `user_A` attempts to create `/telemetry/user_A/events/ev_1` when `/telemetry/user_A` does not exist before or after the batch. -> `PERMISSION_DENIED`
12. **Path ID Poisoning**: User attempts to create `/nicks/invalid id with spaces!` or >128 char ID. -> `PERMISSION_DENIED`
