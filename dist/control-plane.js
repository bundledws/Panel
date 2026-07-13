import { createToken, hashSecret } from "./env.js";
import { hashPassword, verifyPassword, createSessionSecrets, sessionExpiresAt } from "./auth.js";
import * as store from "./store.js";
export class ControlPlane {
    async setupAdmin(email, password) {
        if (store.hasAdmin())
            throw new Error("Admin already exists");
        const passwordHash = await hashPassword(password);
        const user = {
            id: createToken(16),
            email: email.toLowerCase(),
            passwordHash,
            role: "admin",
            suspendedAt: null,
            createdAt: new Date().toISOString()
        };
        store.createUser(user);
        return { id: user.id, email: user.email, role: user.role };
    }
    async hasAdmin() {
        return store.hasAdmin();
    }
    async login(email, password) {
        const user = store.findUserByEmail(email);
        if (!user || user.suspendedAt)
            throw new Error("Invalid email or password");
        if (!(await verifyPassword(password, user.passwordHash)))
            throw new Error("Invalid email or password");
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
    async authenticateSession(sessionToken) {
        const tokenHash = hashSecret(sessionToken);
        const session = store.findSessionByTokenHash(tokenHash);
        if (!session || new Date(session.expiresAt).getTime() <= Date.now()) {
            throw new Error("Unauthorized");
        }
        const user = store.findUserById(session.userId);
        if (!user || user.suspendedAt)
            throw new Error("Unauthorized");
        return {
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
                suspendedAt: user.suspendedAt ? new Date(user.suspendedAt) : null
            },
            session: {
                id: session.id,
                csrfToken: session.csrfToken,
                expiresAt: new Date(session.expiresAt)
            }
        };
    }
    async logout(sessionToken) {
        store.deleteSession(hashSecret(sessionToken));
    }
    /** Create a customer account with limited (app-only) access */
    async createCustomer(email, password) {
        if (!store.hasAdmin())
            throw new Error("No admin configured. Please run setup first.");
        const passwordHash = await hashPassword(password);
        const user = {
            id: createToken(16),
            email: email.toLowerCase(),
            passwordHash,
            role: "customer",
            suspendedAt: null,
            createdAt: new Date().toISOString()
        };
        store.createUser(user);
        return { id: user.id, email: user.email, role: user.role };
    }
}
//# sourceMappingURL=control-plane.js.map