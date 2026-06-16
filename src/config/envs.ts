import 'dotenv/config';
import { get } from 'env-var';

export const envs = {
  // Servidor
  HOST: get('HOST').required().asString(),
  PORT: get('PORT').required().asPortNumber(),

  // PostgreSQL
  HOST_DB: get('HOST_DB').required().asString(),
  PORT_DB: get('PORT_DB').required().asPortNumber(),
  USERNAME_DB: get('USERNAME_DB').required().asString(),
  PASSWORD_DB: get('PASSWORD_DB').asString(),
  DATABASE_DB: get('DATABASE_DB').required().asString(),

  // Seed admin
  ADMIN_SEED_ENABLED: get('ADMIN_SEED_ENABLED').default('true').asBool(),
  ADMIN_SEED_NAME: get('ADMIN_SEED_NAME').default('Admin').asString(),
  ADMIN_SEED_USERNAME: get('ADMIN_SEED_USERNAME').default('admin@local.dev').asString(),
  ADMIN_SEED_PASSWORD: get('ADMIN_SEED_PASSWORD').default('Admin123').asString(),

  // JWT
  JWT_SEED: get('JWT_SEED').required().asString(),
};
