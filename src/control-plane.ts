import { createToken, hashSecret } from "./env.js";
import { hashPassword, verifyPassword, createSessionSecrets, sessionExpiresAt } from "./auth.js";
import * as store from "./store.js";

export type UserRole = "customer" | "admin";

export type SessionPrincipal = {
  user: { id: string; email: string; role: UserRole; suspendedAt: Date | null };
  session: { id: string; csrfToken: string; expiresAt: Date };
};

export class ControlPlane {
  async setupAdmin(email: string, password: string) {
    if (store.hasAdmin()) throw new Error("Admin already exists");
    const passwordHash = await hashPassword(password);
    const user = {
      id: createToken(16),
      email: email.toLowerCase(),
      passwordHash,
      role: "admin" as UserRole,
      suspendedAt: null,
      createdAt: new Date().toISOString()
    };
    store.createUser(user);
    return { id: user.id, email: user.email, role: user.role };
  }

  async hasAdmin(): Promise<boolean> {
    return store.hasAdmin();
  }

  async login(email: string, password: string) {
    const user = store.findUserByEmail(email);
    if (!user || user.suspendedAt) throw new Error("Invalid email or password");
    if (!(await verifyPassword(password, user.passwordHash))) throw new Error("Invalid email or password");

    const { sessionToken, tokenHash, csrfToken } = createSessionSecrets();
    const expiresAt = sessionExpiresAt();

    store.createSession({
      id: createToken(16),
      userId: user.id,
      tokenHash,
      csrfToken,
      expiresAt: expiresAt.toISOString(),
      createdAt: new Date().toISOString()
    });

    return {
      sessionToken,
      csrfToken,
      expiresAt,
      user: { id: user.id, email: user.email, role: user.role }
    };
  }

  async authenticateSession(sessionToken: string): Promise<SessionPrincipal> {
    const tokenHash = hashSecret(sessionToken);
    const session = store.findSessionByTokenHash(tokenHash);

    if (!session || new Date(session.expiresAt).getTime() <= Date.now()) {
      throw new Error("Unauthorized");
    }

    const user = store.findUserById(session.userId);
    if (!user || user.suspendedAt) throw new Error("Unauthorized");

    return {
      user: {
        id: user.id,
        email: user.email,
        role: user.role as UserRole,
        suspendedAt: user.suspendedAt ? new Date(user.suspendedAt) : null
      },
      session: {
        id: session.id,
        csrfToken: session.csrfToken,
        expiresAt: new Date(session.expiresAt)
      }
    };
  }

  async logout(sessionToken: string) {
    store.deleteSession(hashSecret(sessionToken));
  }

  /** Create a customer account with limited (app-only) access */
  async createCustomer(email: string, password: string) {
    if (!store.hasAdmin()) throw new Error("No admin configured. Please run setup first.");
    const passwordHash = await hashPassword(password);
    const user = {
      id: createToken(16),
      email: email.toLowerCase(),
      passwordHash,
      role: "customer" as UserRole,
      suspendedAt: null,
      createdAt: new Date().toISOString()
    };
    store.createUser(user);
    return { id: user.id, email: user.email, role: user.role };
  }
}