import { BcryptAdapter } from "../../config";
import { User } from "./entities";
import { PostgresDatabase } from "./postgres-database";

interface SeedAdminOptions {
    enabled: boolean;
    name: string;
    username: string;
    password: string;
}

export class SeedAdmin {
    static async run(options: SeedAdminOptions): Promise<void> {
        if (!options.enabled) {
            console.log("Admin seed disabled");
            return;
        }

        const username = options.username.trim().toLowerCase();
        const name = options.name.trim();

        if (!username || !name || !options.password) {
            throw new Error("Admin seed requires name, username and password");
        }

        const repository = PostgresDatabase.dataSource.getRepository(User);
        const existingUser = await repository.findOne({
            where: [
                { username },
                { email: username },
            ],
        });

        const password = BcryptAdapter.hash(options.password);

        if (!existingUser) {
            const adminUser = repository.create({
                name,
                username,
                email: username,
                password,
                role: "admin",
                is_active: true,
                is_disabled: false,
                is_google: false,
            });

            await repository.save(adminUser);
            console.log(`Admin user created: ${username}`);
            return;
        }

        existingUser.name = name;
        existingUser.username = username;
        existingUser.email = username;
        existingUser.password = password;
        existingUser.role = "admin";
        existingUser.is_active = true;
        existingUser.is_disabled = false;

        await repository.save(existingUser);
        console.log(`Admin user ensured: ${username}`);
    }
}
