import { ControlPlane } from "./control-plane.js";
import readline from "node:readline";
async function main() {
    const cp = new ControlPlane();
    if (await cp.hasAdmin()) {
        console.log("Admin user already exists. Setup is complete.");
        return;
    }
    // Check for command-line arguments (for scripted installs)
    const args = process.argv.slice(2);
    let email;
    let password;
    if (args.length >= 2) {
        email = args[0];
        password = args[1];
    }
    else {
        // Interactive mode
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        email = await new Promise((resolve) => {
            rl.question("Enter admin email: ", (answer) => resolve(answer.trim()));
        });
        password = await new Promise((resolve) => {
            rl.question("Enter admin password (min 8 chars): ", (answer) => resolve(answer.trim()));
        });
        rl.close();
    }
    if (!email || !password || password.length < 8) {
        console.error("Email and password (min 8 chars) are required.");
        process.exit(1);
    }
    try {
        await cp.setupAdmin(email, password);
        console.log(`Admin user created: ${email}`);
    }
    catch (err) {
        console.error("Setup failed:", err.message);
        process.exit(1);
    }
}
main().catch((err) => {
    console.error("Setup error:", err);
    process.exit(1);
});
//# sourceMappingURL=setup.js.map