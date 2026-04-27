import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { DatabaseSync } = require("node:sqlite") as { DatabaseSync: any };
import fs from "node:fs";
import path from "node:path";

const file = process.env.DB_FILE ?? "./data/secureshift.db";
const postgresConfigured = Boolean(process.env.DB_URL ?? process.env.SUPABASE_DB_URL);
export const db: any = postgresConfigured
  ? { prepare() { throw new Error("SQLite adapter is disabled while DB_URL/SUPABASE_DB_URL is configured"); } }
  : new DatabaseSync(file);
if (!postgresConfigured) fs.mkdirSync(path.dirname(file), { recursive: true });
if (!postgresConfigured) db.exec(`
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','manager','worker')), phone TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS shifts (id TEXT PRIMARY KEY, title TEXT NOT NULL, starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, location TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('open','assigned','completed','cancelled')), assignee_id TEXT REFERENCES users(id), created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS otp_challenges (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), code_hash TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT);
CREATE TABLE IF NOT EXISTS refresh_sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), token_hash TEXT UNIQUE NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_logs (id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, metadata_json TEXT NOT NULL, created_at TEXT NOT NULL);
`);
