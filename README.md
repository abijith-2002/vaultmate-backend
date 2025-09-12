# Project Repository

This backend now delegates all authentication (sign up, login, refresh, and user identity) to Supabase Auth.

Environment variables required (set via .env; do not hardcode in code):
- SUPABASE_URL
- SUPABASE_ANON_KEY
- VM_ADMIN_INVITE_CODE (optional, to grant 'admin' role on registration when invite code matches)

Auth endpoints:
- POST /auth/register: Creates user via Supabase Auth, sets user_metadata (full_name, roles when admin invite matches).
- POST /auth/login: Delegates to Supabase password grant; returns access and refresh tokens from Supabase.
- POST /auth/refresh: Uses Supabase refresh token to obtain new tokens.
- GET /me: Validates Supabase access token and returns user profile derived from Supabase /auth/v1/user.

All MFA flows and local password hashing/storage have been removed.