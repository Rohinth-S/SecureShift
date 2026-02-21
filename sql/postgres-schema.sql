-- Managed Supabase Postgres schema for SecureShift.
-- The API uses a server-side connection; RLS is enabled as defense in depth.
CREATE TABLE IF NOT EXISTS secureshift_users (id uuid PRIMARY KEY, email text UNIQUE NOT NULL, role text NOT NULL CHECK (role IN ('admin','manager','worker')), password_hash text NOT NULL, phone text, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS secureshift_shifts (id uuid PRIMARY KEY, title text NOT NULL, starts_at timestamptz NOT NULL, ends_at timestamptz NOT NULL, location text NOT NULL, status text NOT NULL CHECK (status IN ('open','assigned','completed','cancelled')), assignee_id uuid REFERENCES secureshift_users(id), created_by uuid NOT NULL REFERENCES secureshift_users(id), created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS secureshift_otp_challenges (id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES secureshift_users(id), code_hash text NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz);
CREATE TABLE IF NOT EXISTS secureshift_audit_logs (id uuid PRIMARY KEY, actor_id uuid NOT NULL REFERENCES secureshift_users(id), action text NOT NULL, entity_type text NOT NULL, entity_id uuid NOT NULL, metadata jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS secureshift_shifts_starts_at_idx ON secureshift_shifts(starts_at);
CREATE INDEX IF NOT EXISTS secureshift_audit_created_at_idx ON secureshift_audit_logs(created_at DESC);
ALTER TABLE secureshift_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE secureshift_shifts ENABLE ROW LEVEL SECURITY;
ALTER TABLE secureshift_otp_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE secureshift_audit_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY service_role_full_access ON secureshift_users FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_full_access ON secureshift_shifts FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_full_access ON secureshift_otp_challenges FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY service_role_full_access ON secureshift_audit_logs FOR ALL TO service_role USING (true) WITH CHECK (true);
