import crypto from "node:crypto";
import jwt from "jsonwebtoken";

const secret=process.env.JWT_SECRET ?? "unsafe-development-secret";
export type Role="admin"|"manager"|"worker";
export type Claims={sub:string,email:string,role:Role};
export function hashPassword(password:string){return crypto.scryptSync(password, "secureshift-v1", 32).toString("hex");}
export function signToken(c:Claims){return jwt.sign(c,secret,{expiresIn:"2h",issuer:"secureshift"});}
export function verifyToken(token:string){return jwt.verify(token,secret,{issuer:"secureshift"}) as Claims;}
export function hashOtp(code:string){return crypto.createHash("sha256").update(code).digest("hex");}
