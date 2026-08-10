# Smart LMS Invite Link System Audit & Comparative Analysis

## 1. Authoritative Invite Dependency Map

### Invite Creation Flow
```
Invite creation
    ↓
existing API action: generateInvite(role, email) [src/lib/api-actions.ts]
    ↓
existing API route: POST /api/v1/auth { action: 'generate-invite' } [src/app/api/v1/auth/route.ts]
    ↓
AuthService.generateInvite(user, role, email) [src/lib/services/auth.service.ts]
    ↓
authDb.createInvite(data) [src/lib/database/auth.db.ts]
    ↓
database (invites table)
```

### Invite Acceptance Flow
```
Invite acceptance
    ↓
existing invite route/action: GET /api/v1/auth/invite/accept?token=token [src/app/api/v1/auth/invite/accept/route.ts]
    ↓
AuthService.validateInvite(token) [src/lib/services/auth.service.ts]
    ↓
authDb.findInviteByHash(tokenHash) [src/lib/database/auth.db.ts]
    ↓
database (invites table)
```

### Signup Flow
```
Signup
    ↓
existing signup action: signup(userData) [src/lib/api-actions.ts]
    ↓
existing API route: POST /api/v1/auth { action: 'signup' } [src/app/api/v1/auth/route.ts]
    ↓
AuthService.signup(data, inviteId) [src/lib/services/auth.service.ts]
    ↓
authDb.register(data) [src/lib/database/auth.db.ts]
    ↓
database (users table)
```

### Invite Redemption Flow (Harden Target)
```
AuthService Invariant Validation
    ↓
existing database adapter (authDb.consumeInvite)
    ↓
atomic database state transition (used_at update with conditional filters)
```

---

## 2. Identified Defects & Architectural Gaps

### A. Incorrect Trust Boundary (Cookie as Auth Source)
- **Problem:** The API route reads email and role constraints from the `app-invite-session` cookie and passes them to `AuthService.signup`. However, this cookie is not cryptographically signed or encrypted, and there is no verification inside the service layer mapping back to the database record using the parsed `inviteId`. A client could manipulate their local cookie headers to specify a different role (e.g., `'admin'`) or email, completely bypassing the original bounds of the generated invite.
- **Remediation:** `AuthService.signup()` must fetch the authoritative database record using the `inviteId` and strictly enforce that the requested signup `role` and normalized `email` match the database's record.

### B. Race Condition & Lack of Atomic Consumption
- **Problem:** Currently, the signup process is:
  ```
  Validate validation rules -> register user -> mark invite as used
  ```
  This is a classic "time-of-check to time-of-use" (TOCTOU) bug. Multiple concurrent signup requests using the same `inviteId` could register multiple users under the same single-use invite because the invite is not atomically flagged as consumed prior to/or within user registration.
- **Remediation:** Implement `consumeInvite(id)` in `authDb` which atomically updates the record only if `used_at IS NULL`. Execute this atomic consumption *before* user registration.

### C. Inconsistent Persistence (Lack of Rollback)
- **Problem:** If we consume the invite first, but the registration fails (e.g., due to temporary database downtime, lockups, or edge cases), the invite remains marked as used, leaving a valid user locked out.
- **Remediation:** Introduce an `unconsumeInvite(id)` mechanism to cleanly revert/rollback the consumption in case registration fails.

### D. Missing Email and Role Generation Hardening
- **Problem:** During invite creation, the recipient email address is not strictly validated against system rules or normalized to lowercase.
- **Remediation:** Validate the email using the existing `validateEmail()` rule during invite creation, and store it in normalized lowercase format.
