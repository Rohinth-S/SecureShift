import { Pool } from "pg";
import { db } from "./db.js";

export type UserRow = { id: string; email: string; password_hash: string; role: "admin" | "manager" | "worker"; phone: string | null; created_at: string };
export type ShiftRow = { id: string; title: string; starts_at: string; ends_at: string; location: string; status: "open" | "assigned" | "completed" | "cancelled"; assignee_id: string | null; created_by: string; created_at: string };
export type OtpRow = { id: string; user_id: string; code_hash: string; expires_at: string; consumed_at: string | null };
export type AuditRow = { id: string; actor_id: string; action: string; entity_type: string; entity_id: string; metadata_json: string; created_at: string };

export interface SecureShiftRepository {
  readonly mode: "sqlite" | "postgres";
  createUser(row: UserRow): Promise<void>;
  findUserByEmail(email: string): Promise<UserRow | undefined>;
  findUserById(id: string): Promise<UserRow | undefined>;
  createOtp(row: OtpRow): Promise<void>;
  findActiveOtp(id: string, userId: string): Promise<OtpRow | undefined>;
  consumeOtp(id: string, consumedAt: string): Promise<void>;
  listShifts(): Promise<ShiftRow[]>;
  createShift(row: ShiftRow): Promise<void>;
  findShift(id: string): Promise<ShiftRow | undefined>;
  assignShift(id: string, workerId: string): Promise<boolean>;
  completeShift(id: string): Promise<boolean>;
  appendAudit(row: AuditRow): Promise<void>;
  listAudit(limit: number): Promise<AuditRow[]>;
  close?(): Promise<void>;
}

export class SqliteRepository implements SecureShiftRepository {
  readonly mode = "sqlite" as const;
  async createUser(row: UserRow) { db.prepare("INSERT INTO users VALUES (?,?,?,?,?,?)").run(row.id, row.email, row.password_hash, row.role, row.phone, row.created_at); }
  async findUserByEmail(email: string) { return db.prepare("SELECT * FROM users WHERE email=?").get(email) as UserRow | undefined; }
  async findUserById(id: string) { return db.prepare("SELECT * FROM users WHERE id=?").get(id) as UserRow | undefined; }
  async createOtp(row: OtpRow) { db.prepare("INSERT INTO otp_challenges VALUES (?,?,?,?,?)").run(row.id, row.user_id, row.code_hash, row.expires_at, row.consumed_at); }
  async findActiveOtp(id: string, userId: string) { return db.prepare("SELECT * FROM otp_challenges WHERE id=? AND user_id=? AND consumed_at IS NULL").get(id, userId) as OtpRow | undefined; }
  async consumeOtp(id: string, consumedAt: string) { db.prepare("UPDATE otp_challenges SET consumed_at=? WHERE id=?").run(consumedAt, id); }
  async listShifts() { return db.prepare("SELECT * FROM shifts ORDER BY starts_at").all() as ShiftRow[]; }
  async createShift(row: ShiftRow) { db.prepare("INSERT INTO shifts VALUES (?,?,?,?,?,?,?,?,?)").run(row.id, row.title, row.starts_at, row.ends_at, row.location, row.status, row.assignee_id, row.created_by, row.created_at); }
  async findShift(id: string) { return db.prepare("SELECT * FROM shifts WHERE id=?").get(id) as ShiftRow | undefined; }
  async assignShift(id: string, workerId: string) { const result = db.prepare("UPDATE shifts SET assignee_id=?,status='assigned' WHERE id=? AND status='open'").run(workerId, id); return Number(result.changes) === 1; }
  async completeShift(id: string) { const result = db.prepare("UPDATE shifts SET status='completed' WHERE id=? AND status='assigned'").run(id); return Number(result.changes) === 1; }
  async appendAudit(row: AuditRow) { db.prepare("INSERT INTO audit_logs VALUES (?,?,?,?,?,?,?)").run(row.id, row.actor_id, row.action, row.entity_type, row.entity_id, row.metadata_json, row.created_at); }
  async listAudit(limit: number) { return db.prepare("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?").all(limit) as AuditRow[]; }
}

export class PostgresRepository implements SecureShiftRepository {
  readonly mode = "postgres" as const;
  private readonly ready: Promise<void>;
  constructor(private readonly pool: Pool) { this.ready = this.initialize(); }
  private async initialize() {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','manager','worker')), phone TEXT, created_at TIMESTAMPTZ NOT NULL);
      CREATE TABLE IF NOT EXISTS shifts (id TEXT PRIMARY KEY, title TEXT NOT NULL, starts_at TIMESTAMPTZ NOT NULL, ends_at TIMESTAMPTZ NOT NULL, location TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('open','assigned','completed','cancelled')), assignee_id TEXT REFERENCES users(id), created_by TEXT NOT NULL REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL);
      CREATE TABLE IF NOT EXISTS otp_challenges (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), code_hash TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ);
      CREATE TABLE IF NOT EXISTS audit_logs (id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, metadata_json TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL);
      CREATE INDEX IF NOT EXISTS shifts_starts_at_idx ON shifts(starts_at);
      CREATE INDEX IF NOT EXISTS audit_created_at_idx ON audit_logs(created_at DESC);
    `);
  }
  private async q(text: string, values: unknown[] = []) { await this.ready; return this.pool.query(text, values); }
  async createUser(row: UserRow) { await this.q("INSERT INTO users (id,email,password_hash,role,phone,created_at) VALUES ($1,$2,$3,$4,$5,$6)", [row.id, row.email, row.password_hash, row.role, row.phone, row.created_at]); }
  async findUserByEmail(email: string) { return (await this.q("SELECT * FROM users WHERE email=$1", [email])).rows[0] as UserRow | undefined; }
  async findUserById(id: string) { return (await this.q("SELECT * FROM users WHERE id=$1", [id])).rows[0] as UserRow | undefined; }
  async createOtp(row: OtpRow) { await this.q("INSERT INTO otp_challenges (id,user_id,code_hash,expires_at,consumed_at) VALUES ($1,$2,$3,$4,$5)", [row.id, row.user_id, row.code_hash, row.expires_at, row.consumed_at]); }
  async findActiveOtp(id: string, userId: string) { return (await this.q("SELECT * FROM otp_challenges WHERE id=$1 AND user_id=$2 AND consumed_at IS NULL", [id, userId])).rows[0] as OtpRow | undefined; }
  async consumeOtp(id: string, consumedAt: string) { await this.q("UPDATE otp_challenges SET consumed_at=$1 WHERE id=$2", [consumedAt, id]); }
  async listShifts() { return (await this.q("SELECT * FROM shifts ORDER BY starts_at")).rows as ShiftRow[]; }
  async createShift(row: ShiftRow) { await this.q("INSERT INTO shifts (id,title,starts_at,ends_at,location,status,assignee_id,created_by,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)", [row.id, row.title, row.starts_at, row.ends_at, row.location, row.status, row.assignee_id, row.created_by, row.created_at]); }
  async findShift(id: string) { return (await this.q("SELECT * FROM shifts WHERE id=$1", [id])).rows[0] as ShiftRow | undefined; }
  async assignShift(id: string, workerId: string) { return (await this.q("UPDATE shifts SET assignee_id=$1,status='assigned' WHERE id=$2 AND status='open'", [workerId, id])).rowCount === 1; }
  async completeShift(id: string) { return (await this.q("UPDATE shifts SET status='completed' WHERE id=$1 AND status='assigned'", [id])).rowCount === 1; }
  async appendAudit(row: AuditRow) { await this.q("INSERT INTO audit_logs (id,actor_id,action,entity_type,entity_id,metadata_json,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)", [row.id, row.actor_id, row.action, row.entity_type, row.entity_id, row.metadata_json, row.created_at]); }
  async listAudit(limit: number) { return (await this.q("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT $1", [limit])).rows as AuditRow[]; }
  async close() { await this.pool.end(); }
}

export function createRepository(): SecureShiftRepository {
  const connectionString = process.env.DB_URL ?? process.env.SUPABASE_DB_URL;
  if (connectionString) {
    return new PostgresRepository(new Pool({ connectionString, ssl: process.env.PGSSLMODE === "disable" ? undefined : { rejectUnauthorized: false }, max: 10 }));
  }
  return new SqliteRepository();
}

export const repository = createRepository();
