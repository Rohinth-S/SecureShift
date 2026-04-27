import crypto from "node:crypto";
import { Pool } from "pg";
import { db } from "./db.js";

export type Role = "admin" | "manager" | "worker";
export type UserRow = {
  id: string; email: string; role: Role; password_hash: string; phone: string | null; created_at: string;
};
export type ShiftRow = {
  id: string; title: string; starts_at: string; ends_at: string; location: string;
  status: "open" | "assigned" | "completed" | "cancelled";
  assignee_id: string | null; created_by: string; created_at: string;
};
export type RefreshSessionRow = {
  id: string; user_id: string; token_hash: string; expires_at: string; revoked_at: string | null; created_at: string;
};
export type QueryExecutor = {
  query: (text: string, values?: unknown[]) => Promise<{ rows: any[]; rowCount?: number }>;
};

export interface SecureShiftRepository {
  readonly mode: "sqlite" | "postgres";
  createUser(row: UserRow): Promise<void>;
  findUserByEmail(email: string): Promise<UserRow | undefined>;
  findUserById(id: string): Promise<UserRow | undefined>;
  createOtp(row: { id: string; user_id: string; code_hash: string; expires_at: string; consumed_at: string | null }): Promise<void>;
  findActiveOtp(id: string, userId: string): Promise<{ id: string; code_hash: string; expires_at: string } | undefined>;
  consumeOtp(id: string, consumedAt: string): Promise<void>;
  listShifts(): Promise<ShiftRow[]>;
  createShift(row: ShiftRow): Promise<void>;
  findShift(id: string): Promise<ShiftRow | undefined>;
  hasOverlappingShift(workerId: string, startsAt: string, endsAt: string, excludeId?: string): Promise<boolean>;
  assignShift(id: string, workerId: string): Promise<boolean>;
  completeShift(id: string): Promise<boolean>;
  createRefreshSession(row: RefreshSessionRow): Promise<void>;
  findRefreshSession(tokenHash: string): Promise<RefreshSessionRow | undefined>;
  revokeRefreshSession(id: string, revokedAt: string): Promise<boolean>;
  appendAudit(row: { id: string; actor_id: string; action: string; entity_type: string; entity_id: string; metadata_json: string; created_at: string }): Promise<void>;
  listAudit(limit: number): Promise<any[]>;
  close(): Promise<void>;
}

class SqliteRepository implements SecureShiftRepository {
  readonly mode = "sqlite" as const;
  async createUser(row: UserRow) { db.prepare("INSERT INTO users VALUES (?,?,?,?,?,?)").run(row.id, row.email, row.password_hash, row.role, row.phone, row.created_at); }
  async findUserByEmail(email: string) { return db.prepare("SELECT id,email,role,password_hash,phone FROM users WHERE email=?").get(email) as UserRow | undefined; }
  async findUserById(id: string) { return db.prepare("SELECT id,email,role,password_hash,phone FROM users WHERE id=?").get(id) as UserRow | undefined; }
  async createOtp(row: { id: string; user_id: string; code_hash: string; expires_at: string; consumed_at: string | null }) { db.prepare("INSERT INTO otp_challenges VALUES (?,?,?,?,?)").run(row.id, row.user_id, row.code_hash, row.expires_at, row.consumed_at); }
  async findActiveOtp(id: string, userId: string) { return db.prepare("SELECT id,code_hash,expires_at FROM otp_challenges WHERE id=? AND user_id=? AND consumed_at IS NULL").get(id, userId) as { id: string; code_hash: string; expires_at: string } | undefined; }
  async consumeOtp(id: string, consumedAt: string) { db.prepare("UPDATE otp_challenges SET consumed_at=? WHERE id=? AND consumed_at IS NULL").run(consumedAt, id); }
  async listShifts() { return db.prepare("SELECT * FROM shifts ORDER BY starts_at").all() as ShiftRow[]; }
  async createShift(row: ShiftRow) { db.prepare("INSERT INTO shifts VALUES (?,?,?,?,?,?,?,?,?)").run(row.id, row.title, row.starts_at, row.ends_at, row.location, row.status, row.assignee_id, row.created_by, row.created_at); }
  async findShift(id: string) { return db.prepare("SELECT * FROM shifts WHERE id=?").get(id) as ShiftRow | undefined; }
  async hasOverlappingShift(workerId: string, startsAt: string, endsAt: string, excludeId?: string) {
    const row = db.prepare("SELECT 1 AS conflict FROM shifts WHERE assignee_id=? AND status IN ('assigned','open') AND starts_at < ? AND ends_at > ? AND (? IS NULL OR id <> ?) LIMIT 1").get(workerId, endsAt, startsAt, excludeId ?? null, excludeId ?? null) as { conflict: number } | undefined;
    return Boolean(row);
  }
  async assignShift(id: string, workerId: string) { return Number(db.prepare("UPDATE shifts SET assignee_id=?,status='assigned' WHERE id=? AND status='open'").run(workerId, id).changes) === 1; }
  async completeShift(id: string) { return Number(db.prepare("UPDATE shifts SET status='completed' WHERE id=? AND status='assigned'").run(id).changes) === 1; }
  async createRefreshSession(row: RefreshSessionRow) { db.prepare("INSERT INTO refresh_sessions VALUES (?,?,?,?,?,?)").run(row.id, row.user_id, row.token_hash, row.expires_at, row.revoked_at, row.created_at); }
  async findRefreshSession(tokenHash: string) { return db.prepare("SELECT * FROM refresh_sessions WHERE token_hash=?").get(tokenHash) as RefreshSessionRow | undefined; }
  async revokeRefreshSession(id: string, revokedAt: string) { return Number(db.prepare("UPDATE refresh_sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL").run(revokedAt, id).changes) === 1; }
  async appendAudit(row: { id: string; actor_id: string; action: string; entity_type: string; entity_id: string; metadata_json: string; created_at: string }) { db.prepare("INSERT INTO audit_logs VALUES (?,?,?,?,?,?,?)").run(row.id, row.actor_id, row.action, row.entity_type, row.entity_id, row.metadata_json, row.created_at); }
  async listAudit(limit: number) { return db.prepare("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?").all(limit); }
  async close() {}
}

class PostgresRepository implements SecureShiftRepository {
  readonly mode = "postgres" as const;
  constructor(private readonly executor: QueryExecutor, private readonly pool?: Pool) {}
  async createUser(row: UserRow) { await this.executor.query("INSERT INTO secureshift_users (id,email,password_hash,role,phone,created_at) VALUES ($1,$2,$3,$4,$5,$6)", [row.id, row.email, row.password_hash, row.role, row.phone, row.created_at]); }
  async findUserByEmail(email: string) { const result = await this.executor.query("SELECT id,email,role,password_hash,phone FROM secureshift_users WHERE email=$1", [email]); return result.rows[0] as UserRow | undefined; }
  async findUserById(id: string) { const result = await this.executor.query("SELECT id,email,role,password_hash,phone FROM secureshift_users WHERE id=$1", [id]); return result.rows[0] as UserRow | undefined; }
  async createOtp(row: { id: string; user_id: string; code_hash: string; expires_at: string; consumed_at: string | null }) { await this.executor.query("INSERT INTO secureshift_otp_challenges (id,user_id,code_hash,expires_at,consumed_at) VALUES ($1,$2,$3,$4,$5)", [row.id, row.user_id, row.code_hash, row.expires_at, row.consumed_at]); }
  async findActiveOtp(id: string, userId: string) { const result = await this.executor.query("SELECT id,code_hash,expires_at FROM secureshift_otp_challenges WHERE id=$1 AND user_id=$2 AND consumed_at IS NULL", [id, userId]); return result.rows[0] as { id: string; code_hash: string; expires_at: string } | undefined; }
  async consumeOtp(id: string, consumedAt: string) { await this.executor.query("UPDATE secureshift_otp_challenges SET consumed_at=$1 WHERE id=$2 AND consumed_at IS NULL", [consumedAt, id]); }
  async listShifts() { const result = await this.executor.query("SELECT * FROM secureshift_shifts ORDER BY starts_at"); return result.rows as ShiftRow[]; }
  async createShift(row: ShiftRow) { await this.executor.query("INSERT INTO secureshift_shifts (id,title,starts_at,ends_at,location,status,assignee_id,created_by,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)", [row.id, row.title, row.starts_at, row.ends_at, row.location, row.status, row.assignee_id, row.created_by, row.created_at]); }
  async findShift(id: string) { const result = await this.executor.query("SELECT * FROM secureshift_shifts WHERE id=$1", [id]); return result.rows[0] as ShiftRow | undefined; }
  async hasOverlappingShift(workerId: string, startsAt: string, endsAt: string, excludeId?: string) { const result = await this.executor.query("SELECT 1 FROM secureshift_shifts WHERE assignee_id=$1 AND status IN ('assigned','open') AND starts_at < $2 AND ends_at > $3 AND ($4::uuid IS NULL OR id <> $4::uuid) LIMIT 1", [workerId, endsAt, startsAt, excludeId ?? null]); return result.rows.length > 0; }
  async assignShift(id: string, workerId: string) { const result = await this.executor.query("UPDATE secureshift_shifts SET assignee_id=$1,status='assigned' WHERE id=$2 AND status='open'", [workerId, id]); return result.rowCount === 1; }
  async completeShift(id: string) { const result = await this.executor.query("UPDATE secureshift_shifts SET status='completed' WHERE id=$1 AND status='assigned'", [id]); return result.rowCount === 1; }
  async createRefreshSession(row: RefreshSessionRow) { await this.executor.query("INSERT INTO secureshift_refresh_sessions (id,user_id,token_hash,expires_at,revoked_at,created_at) VALUES ($1,$2,$3,$4,$5,$6)", [row.id, row.user_id, row.token_hash, row.expires_at, row.revoked_at, row.created_at]); }
  async findRefreshSession(tokenHash: string) { const result = await this.executor.query("SELECT id,user_id,token_hash,expires_at,revoked_at,created_at FROM secureshift_refresh_sessions WHERE token_hash=$1", [tokenHash]); return result.rows[0] as RefreshSessionRow | undefined; }
  async revokeRefreshSession(id: string, revokedAt: string) { const result = await this.executor.query("UPDATE secureshift_refresh_sessions SET revoked_at=$1 WHERE id=$2 AND revoked_at IS NULL", [revokedAt, id]); return result.rowCount === 1; }
  async appendAudit(row: { id: string; actor_id: string; action: string; entity_type: string; entity_id: string; metadata_json: string; created_at: string }) { await this.executor.query("INSERT INTO secureshift_audit_logs (id,actor_id,action,entity_type,entity_id,metadata,created_at) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)", [row.id, row.actor_id, row.action, row.entity_type, row.entity_id, row.metadata_json, row.created_at]); }
  async listAudit(limit: number) { const result = await this.executor.query("SELECT id,actor_id,action,entity_type,entity_id,metadata::text AS metadata_json,created_at FROM secureshift_audit_logs ORDER BY created_at DESC LIMIT $1", [limit]); return result.rows; }
  async close() { await this.pool?.end(); }
}

const POSTGRES_SCHEMA = `
CREATE TABLE IF NOT EXISTS secureshift_users (id UUID PRIMARY KEY,email TEXT UNIQUE NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','manager','worker')),password_hash TEXT NOT NULL,phone TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS secureshift_shifts (id UUID PRIMARY KEY,title TEXT NOT NULL,starts_at TIMESTAMPTZ NOT NULL,ends_at TIMESTAMPTZ NOT NULL,location TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('open','assigned','completed','cancelled')),assignee_id UUID REFERENCES secureshift_users(id),created_by UUID NOT NULL REFERENCES secureshift_users(id),created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS secureshift_otp_challenges (id UUID PRIMARY KEY,user_id UUID NOT NULL REFERENCES secureshift_users(id),code_hash TEXT NOT NULL,expires_at TIMESTAMPTZ NOT NULL,consumed_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS secureshift_refresh_sessions (id UUID PRIMARY KEY,user_id UUID NOT NULL REFERENCES secureshift_users(id),token_hash TEXT UNIQUE NOT NULL,expires_at TIMESTAMPTZ NOT NULL,revoked_at TIMESTAMPTZ,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS secureshift_audit_logs (id UUID PRIMARY KEY,actor_id UUID NOT NULL REFERENCES secureshift_users(id),action TEXT NOT NULL,entity_type TEXT NOT NULL,entity_id UUID NOT NULL,metadata JSONB NOT NULL DEFAULT '{}'::jsonb,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
ALTER TABLE secureshift_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE secureshift_shifts ENABLE ROW LEVEL SECURITY;
ALTER TABLE secureshift_otp_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE secureshift_refresh_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE secureshift_audit_logs ENABLE ROW LEVEL SECURITY;`;

export function createLocalRepository(): SecureShiftRepository { return new SqliteRepository(); }
export function createPostgresRepositoryFromExecutor(executor: QueryExecutor): SecureShiftRepository { return new PostgresRepository(executor); }
export async function createRepository(): Promise<SecureShiftRepository> {
  const connectionString = process.env.DB_URL ?? process.env.SUPABASE_DB_URL;
  if (!connectionString) return createLocalRepository();
  const pool = new Pool({ connectionString, ssl: process.env.PGSSLMODE === "disable" ? undefined : { rejectUnauthorized: false }, max: 10 });
  return new PostgresRepository(pool, pool);
}

export const repository = process.env.DB_URL || process.env.SUPABASE_DB_URL
  ? new PostgresRepository(new Pool({ connectionString: process.env.DB_URL ?? process.env.SUPABASE_DB_URL, ssl: process.env.PGSSLMODE === "disable" ? undefined : { rejectUnauthorized: false }, max: 10 }))
  : new SqliteRepository();


