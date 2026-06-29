# Module 15 — Design Decisions

## Why a fake "bank" (ChainBank)?
Banking-style apps make the impact of attack chains visceral. Account takeover on a bank is not a demo — it has obvious real-world consequences. Instructors have found that "alert(1) on a bank" lands differently than "alert(1) on a blog."

## Why no HttpOnly on the session cookie?
The first chain (P01: cookie theft) requires a readable session cookie. Module 17's defense demos add HttpOnly. This deliberate absence makes the vulnerability visible.

## Why no current-password check on change-password?
Most account-takeover chains depend on this. /auth/change-password accepts a valid CSRF token — which XSS can harvest — and changes the password without re-authentication. The defense (requiring the current password) is described in tutorial.html's defense table.

## Why both /auth/profile and /auth/users?
/auth/profile is user-context stored XSS (affects profile viewers).
/auth/users is admin-context stored XSS — the same bio payload fires with admin privileges when an admin views the user list. This demonstrates vertical privilege escalation via stored XSS.

## Why a separate OOB receiver on port 5001?
Keeps exfiltration traffic separate from app traffic. Real attackers use out-of-band domains; the separate port simulates this while staying localhost-only for lab safety.
