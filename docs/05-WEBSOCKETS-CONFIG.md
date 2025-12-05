# WebSockets y Configuración

Esta sección documenta la implementación de WebSockets con Socket.io y la configuración general.

---

## 1. WebSockets Handler

### Sockets Class

**Archivo**: `src/presentation/sockets.ts`

```typescript
import { Socket } from 'socket.io'; 
import { JwtAdapter } from '../config';
import { userConnected, userDisconnected } from '../infrastructure/sockets/users.envent';

export class Sockets {
  public static instance: Sockets;
  public readonly io: any;

  public constructor(io: any) {
    this.io = io;
  }

  public static getInstance(io?: any): Sockets {
    if (!Sockets.instance && io) {
      Sockets.instance = new Sockets(io);
    }
    return Sockets.instance;
  }

  handleEvents() {
    // Evento principal de conexión
    this.io.on('connection', async (socket: Socket) => {
      console.log('Socket connected, verifying token...');

      try {
        const token =
          socket.handshake.query.Authorization?.toString().replace("Bearer ", "") ||
          socket.handshake.auth?.token;

        if (!token) {
          console.warn("No token provided, disconnecting socket.");
          console.log("Detalles del socket en ausencia de token:", {
            handshakeQuery: socket.handshake.query,
            handshakeAuth: socket.handshake.auth,
          });
          return socket.disconnect();
        }

        // Extendemos el payload para incluir entity y profileId
        const payload = await JwtAdapter.validateToken<{ uid: string, entity: string, profileId?: string }>(token);

        if (!payload) {
          console.log('Invalid token');
          return socket.disconnect();
        }

        // Usamos profileId si existe; de lo contrario, usamos uid
        socket.join(payload.uid);
        console.log('Cliente conectado', payload.uid);
        await userConnected(payload.uid);

        socket.on("disconnect", async (reason) => {
          console.log('Cliente desconectado', { reason, socketId: socket.id });
          console.log("Salas antes de desconectar:", Array.from(socket.rooms));
          await userDisconnected(payload.uid);
        });

        socket.on("error", (error) => {
          console.error("⚠️ Error en el socket:", error);
        });

      } catch (error) {
        console.error('Token validation error:', error);
        socket.disconnect();
      }
    });
  }
}
```

**Equivalente NestJS (WebSocket Gateway)**:

```typescript
// src/gateways/user.gateway.ts
import {
  WebSocketGateway,
  WebSocketServer,
  OnGatewayConnection,
  OnGatewayDisconnect,
  OnGatewayInit,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../database/entities/user.entity';

interface JwtPayload {
  uid: string;
  entity?: string;
  profileId?: string;
}

@WebSocketGateway({
  cors: {
    origin: '*',
  },
})
export class UserGateway implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect {
  
  @WebSocketServer()
  server: Server;

  constructor(
    private readonly jwtService: JwtService,
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  afterInit(server: Server) {
    console.log('WebSocket Gateway initialized');
  }

  async handleConnection(socket: Socket) {
    console.log('Socket connected, verifying token...');

    try {
      // Obtener token del query o auth
      const token = 
        socket.handshake.query.Authorization?.toString().replace("Bearer ", "") ||
        socket.handshake.auth?.token;

      if (!token) {
        console.warn("No token provided, disconnecting socket.");
        return socket.disconnect();
      }

      // Validar token
      const payload = this.jwtService.verify<JwtPayload>(token);

      if (!payload) {
        console.log('Invalid token');
        return socket.disconnect();
      }

      // Unir a la sala del usuario
      socket.join(payload.uid);
      console.log('Cliente conectado', payload.uid);

      // Actualizar estado online
      await this.userConnected(payload.uid);

      // Guardar uid en el socket para uso posterior
      socket.data.uid = payload.uid;

    } catch (error) {
      console.error('Token validation error:', error);
      socket.disconnect();
    }
  }

  async handleDisconnect(socket: Socket) {
    const uid = socket.data.uid;
    if (uid) {
      console.log('Cliente desconectado', uid);
      await this.userDisconnected(uid);
    }
  }

  private async userConnected(uid: string): Promise<void> {
    const user = await this.userRepository.findOne({ where: { uid } });
    if (user) {
      user.is_online = true;
      await this.userRepository.save(user);
    }
  }

  private async userDisconnected(uid: string): Promise<void> {
    const user = await this.userRepository.findOne({ where: { uid } });
    if (user) {
      user.is_online = false;
      await this.userRepository.save(user);
    }
  }

  // Método para emitir a un usuario específico
  emitToUser(uid: string, event: string, data: any) {
    this.server.to(uid).emit(event, data);
  }

  // Método para emitir a todos los usuarios
  emitToAll(event: string, data: any) {
    this.server.emit(event, data);
  }
}
```

---

### User Socket Events

**Archivo**: `src/infrastructure/sockets/users.envent.ts`

```typescript
import { PostgresDatabase } from "../../data/postgres";
import { User } from "../../data/postgres/entities";

export const userConnected = async (uid: string) => {
    const queryRunner = PostgresDatabase.dataSource.createQueryRunner();
    await queryRunner.connect();
    const user = await queryRunner.manager.findOne(User, {
        where: { uid },
    });
    if (!user) return;
    user.is_online = true;
    await queryRunner.manager.save(user);
    await queryRunner.release();
};

export const userDisconnected = async (uid: string) => {
    const queryRunner = PostgresDatabase.dataSource.createQueryRunner();
    await queryRunner.connect();
    const user = await queryRunner.manager.findOne(User, {
        where: { uid },
    });
    if (!user) return;
    user.is_online = false;
    await queryRunner.manager.save(user);
    await queryRunner.release();
};
```

---

## 2. Configuración Global

### Variables de Entorno

**Archivo**: `src/config/envs.ts`

```typescript
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

  // JWT
  JWT_SEED: get('JWT_SEED').required().asString(),
};
```

**Equivalente NestJS con @nestjs/config**:

```typescript
// src/common/config/configuration.ts
export default () => ({
  host: process.env.HOST || '0.0.0.0',
  port: parseInt(process.env.PORT, 10) || 3500,
  database: {
    host: process.env.HOST_DB,
    port: parseInt(process.env.PORT_DB, 10) || 5432,
    username: process.env.USERNAME_DB,
    password: process.env.PASSWORD_DB || '',
    database: process.env.DATABASE_DB,
  },
  jwt: {
    secret: process.env.JWT_SEED,
    expiresIn: '4h',
  },
});
```

```typescript
// src/common/config/validation.schema.ts
import * as Joi from 'joi';

export const validationSchema = Joi.object({
  HOST: Joi.string().default('0.0.0.0'),
  PORT: Joi.number().default(3500),
  
  HOST_DB: Joi.string().required(),
  PORT_DB: Joi.number().default(5432),
  USERNAME_DB: Joi.string().required(),
  PASSWORD_DB: Joi.string().allow('').default(''),
  DATABASE_DB: Joi.string().required(),
  
  JWT_SEED: Joi.string().required(),
});
```

```typescript
// En app.module.ts
import { ConfigModule } from '@nestjs/config';
import configuration from './common/config/configuration';
import { validationSchema } from './common/config/validation.schema';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validationSchema,
    }),
    // ...otros módulos
  ],
})
export class AppModule {}
```

---

### BcryptAdapter

**Archivo**: `src/config/bcrypt.ts`

```typescript
import { compareSync, hashSync } from 'bcryptjs';

export class BcryptAdapter {

    static hash(password: string): string {
        return hashSync(password);
    }

    static compare(password: string, hashed: string): boolean {
        return compareSync(password, hashed);
    }
}
```

**En NestJS**: Puedes usar directamente `bcryptjs` o crear un servicio:

```typescript
// src/common/services/bcrypt.service.ts
import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class BcryptService {
  private readonly saltRounds = 10;

  hash(password: string): string {
    return bcrypt.hashSync(password, this.saltRounds);
  }

  compare(password: string, hashed: string): boolean {
    return bcrypt.compareSync(password, hashed);
  }
}
```

---

### JwtAdapter

**Archivo**: `src/config/jwt.ts`

```typescript
import jwt from 'jsonwebtoken';
import { envs } from './envs';

export class JwtAdapter {

    static async generateToken(payload: Object, duration: number = 4 * 60 * 60): Promise<string | null> {
        return new Promise((resolve) => {
            jwt.sign(payload, envs.JWT_SEED, { expiresIn: duration }, (err, accessToken) => {
                if (err) {
                    return resolve(null);
                }
                resolve(accessToken!);
            })
        });
    }

    static validateToken<T>(accessToken: string): Promise<T | null> {
        return new Promise((resolve) => {
            jwt.verify(accessToken, envs.JWT_SEED, (err, decoded) => {
                if (err) {
                    return resolve(null);
                }
                resolve(decoded as T);
            })
        });
    }
}
```

**En NestJS**: Usa `@nestjs/jwt`:

```typescript
// El JwtService de @nestjs/jwt ya incluye estas funcionalidades
import { JwtService } from '@nestjs/jwt';

// Generar token
const token = this.jwtService.sign({ uid: user.uid });

// Validar token
const payload = this.jwtService.verify(token);
```

---

### Validators

**Archivo**: `src/config/validators.ts`

```typescript
export class Validators {
  static get email() {
    return /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
  } 
}
```

**En NestJS**: Usa `class-validator`:

```typescript
import { IsEmail } from 'class-validator';

export class UpdateUserDto {
  @IsEmail({}, { message: "Invalid 'email'" })
  email?: string;
}
```

---

## 3. Archivo .env.template

```env
# Servidor
HOST=0.0.0.0
PORT=3500

# PostgreSQL
HOST_DB=localhost
PORT_DB=5432
USERNAME_DB=your_username
PASSWORD_DB=your_password
DATABASE_DB=your_database

# JWT
JWT_SEED=your_jwt_secret_seed
```

---

## 4. Punto de Entrada Principal

### app.ts Original

**Archivo**: `src/app.ts`

```typescript
import { envs } from "./config";
import { PostgresDatabase } from "./data/postgres";
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

        await serverInstance.start();
    } catch (error) {
        console.error("Failed to connect to the database:", error);
        process.exit(1);
    }
})();

export const io = serverInstance.io; // Exportar io
```

**Equivalente NestJS (main.ts)**:

```typescript
// src/main.ts
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  // Configuración global
  app.enableCors();
  app.setGlobalPrefix('api');
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
    transformOptions: {
      enableImplicitConversion: true,
    },
  }));

  // Health check endpoint
  app.use('/health', (req, res) => {
    res.status(200).send('Healthy');
  });

  const host = configService.get<string>('host');
  const port = configService.get<number>('port');

  await app.listen(port, host);
  console.log(`Server is running on HOST ${host} - PORT ${port}`);
}

bootstrap();
```

---

## 5. Gateway Module (NestJS)

```typescript
// src/gateways/gateways.module.ts
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserGateway } from './user.gateway';
import { User } from '../database/entities/user.entity';
import { AuthModule } from '../modules/auth/auth.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    AuthModule,
  ],
  providers: [UserGateway],
  exports: [UserGateway],
})
export class GatewaysModule {}
```

---

## 6. App Module Completo (NestJS)

```typescript
// src/app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from './database/database.module';
import { AuthModule } from './modules/auth/auth.module';
import { UserModule } from './modules/user/user.module';
import { GatewaysModule } from './gateways/gateways.module';
import configuration from './common/config/configuration';
import { validationSchema } from './common/config/validation.schema';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
      validationSchema,
    }),
    DatabaseModule,
    AuthModule,
    UserModule,
    GatewaysModule,
  ],
})
export class AppModule {}
```
