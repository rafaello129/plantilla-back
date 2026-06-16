import { envs } from "./config";
import { PostgresDatabase, SeedAdmin } from "./data/postgres";
import { AppRoutes } from "./presentation/routes";
import { Server } from "./presentation/server";

const serverInstance = new Server({
    host: envs.HOST,
    port: envs.PORT,
    routes: AppRoutes.routes
});


(async () => {
    try {
        await PostgresDatabase.connect({
            host: envs.HOST_DB,
            port: envs.PORT_DB,
            username: envs.USERNAME_DB,
            password: envs.PASSWORD_DB ?? '',
            database: envs.DATABASE_DB,
        });

        await SeedAdmin.run({
            enabled: envs.ADMIN_SEED_ENABLED,
            name: envs.ADMIN_SEED_NAME,
            username: envs.ADMIN_SEED_USERNAME,
            password: envs.ADMIN_SEED_PASSWORD,
        });

        await serverInstance.start();
    } catch (error) {
        console.error("Failed to connect to the database:", error);
        process.exit(1);
    }
})();

export const io = serverInstance.io; // Exportar io
