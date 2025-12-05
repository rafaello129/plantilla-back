# Capa de Presentación (Presentation Layer)

Esta sección documenta los controladores, rutas, middlewares y la configuración del servidor.

---

## 1. Servidor HTTP

### Server Configuration

**Archivo**: `src/presentation/server.ts`

```typescript
import express, { Express, Router } from 'express';
import path from 'path';
import http from 'http';
import { Sockets } from './sockets';
import { Server as WSServer } from 'socket.io';
import cors from 'cors';
import morgan from 'morgan';

interface Options {
    port?: number;
    host?: string;
    routes: Router
}

export class Server {

    public readonly app: Express = express();
    public readonly port: number;
    public readonly host: string;
    public readonly routes: Router;
    private readonly server = http.createServer(this.app);
    public readonly io = new WSServer(this.server)

    constructor(options: Options) {
        const { host = '127.0.0.1', port = 3500, routes } = options;
        this.host = host;
        this.port = port;
        this.routes = routes;
    }

    async start() {
        try {
            // Middleware
            this.app.use(express.json());
            this.app.use(express.urlencoded({ extended: true }));
            this.app.use(cors());

            this.app.use(morgan((tokens, req, res) => {
                return [
                  tokens.method(req, res),
                  tokens.url(req, res),
                  tokens.status(req, res),
                  tokens.res(req, res, 'content-length'), '-',
                  tokens['response-time'](req, res), 'ms'
                ].join(' ')
            }));

            this.app.use(
                "/exports",
                express.static(path.join(__dirname, '../exports'))
            );

            this.app.set('io', this.io);
            // Inicializar sockets
            const sockets = new Sockets(this.io);
            sockets.handleEvents();

            Sockets.getInstance(this.io);

            // Endpoint de salud
            this.app.get('/health', (req, res) => {
                res.status(200).send('Healthy');
            });

            // Rutas
            this.app.use(this.routes);
            this.app.use(express.static(path.resolve(__dirname, './public')));

            // Manejo de errores
            this.app.use((err: any, _req: any, res: any, _next: any) => {
                console.error(err.stack);
                res.status(500).send('Something broke!');
            });

            this.server.listen(this.port, this.host, () => {
                console.log(`Server is running on HOST ${this.host} - PORT ${this.port}`);
            });
        } catch (error) {
            console.error("Failed to start the server:", error);
            process.exit(1);
        }
    }
}
```

**Equivalente NestJS (main.ts)**:

```typescript
// src/main.ts
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  
  // Middleware global
  app.enableCors();
  app.useGlobalPipes(new ValidationPipe({
    whitelist: true,
    forbidNonWhitelisted: true,
    transform: true,
  }));
  
  // Prefijo global de API
  app.setGlobalPrefix('api');
  
  const host = configService.get('HOST') || '0.0.0.0';
  const port = configService.get('PORT') || 3500;
  
  await app.listen(port, host);
  console.log(`Server is running on HOST ${host} - PORT ${port}`);
}
bootstrap();
```

---

## 2. Rutas Principales

### AppRoutes

**Archivo**: `src/presentation/routes.ts`

```typescript
import { Router } from "express";
import { AuthRoutes } from "./auth/routes";
import { UserRoutes } from "./user/routes";

export class AppRoutes {

    static get routes(): Router {

        const router = Router();

        router.use('/api/auth', AuthRoutes.routes);
        router.use('/api/users', UserRoutes.routes);

        return router;
    }
}
```

**Equivalente NestJS (app.module.ts)**:

```typescript
// src/app.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from './database/database.module';
import { AuthModule } from './modules/auth/auth.module';
import { UserModule } from './modules/user/user.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    DatabaseModule,
    AuthModule,
    UserModule,
  ],
})
export class AppModule {}
```

---

## 3. Middlewares

### AuthMiddleware

**Archivo**: `src/presentation/middlewares/auth.middleware.ts`

```typescript
import { Request, Response, NextFunction } from "express";
import { JwtAdapter } from "../../config";
import { PostgresDatabase } from "../../data/postgres";
import { User } from "../../data/postgres/entities";
import { QueryRunner } from "typeorm";

export class AuthMiddleware {
  static validateJwt = async (req: Request, res: Response, next: NextFunction) => {
    const authorization = req.headers['authorization'];
    if (!authorization || !authorization.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Invalid or missing accessToken' });
    }

    const accessToken = authorization.split(' ')[1];
    const queryRunner: QueryRunner = PostgresDatabase.dataSource.createQueryRunner();

    try {
      await queryRunner.connect();
      const payload = await JwtAdapter.validateToken<{ uid: string }>(accessToken);

      if (!payload) {
        return res.status(401).json({ error: 'Invalid accessToken' });
      }

      const user = await queryRunner.manager.findOne(User, {
        where: { uid: payload.uid, is_active: true },
        select: [
          'uid', 'username', 'email', 'phone', 'password', 'is_active',
          'is_online', 'is_disabled', 'is_google', 'created_at',
          'updated_at', 'picture', 'role'
        ]
      });

      if (!user || !user.is_active || user.is_disabled) {
        return res.status(401).json({
          error: user ? (user.is_disabled ? 'User disabled' : 'User inactive') : 'Invalid accessToken'
        });
      }

      delete user.password;
      if(!req.body) {
        req.body = {};
      }
      req.body.user = { ...user };

      next();
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Internal server error' });
    } finally {
      await queryRunner.release();
    }
  };
}
```

**Equivalente NestJS (JWT Strategy + Guard)**:

```typescript
// src/modules/auth/strategies/jwt.strategy.ts
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../../database/entities/user.entity';

interface JwtPayload {
  uid: string;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    configService: ConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('JWT_SEED'),
    });
  }

  async validate(payload: JwtPayload): Promise<User> {
    const { uid } = payload;

    const user = await this.userRepository.findOne({
      where: { uid, is_active: true },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid accessToken');
    }

    if (user.is_disabled) {
      throw new UnauthorizedException('User disabled');
    }

    if (!user.is_active) {
      throw new UnauthorizedException('User inactive');
    }

    delete user.password;
    return user;
  }
}
```

```typescript
// src/common/guards/jwt-auth.guard.ts
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
```

### RoleMiddleware

**Archivo**: `src/presentation/middlewares/role.middleware.ts`

```typescript
import { Request, Response, NextFunction } from "express";
import { UserEntity } from "../../domain/entities";

export class RoleMiddleware {
  static isAdmin = (req: Request, res: Response, next: NextFunction) => {
    const user: UserEntity = req.body.user;

    if (!user) {
        return res.status(500).json({ error: 'Internal server error: user not found in request' });
    }

    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden: Administrator access required' });
    }
    
    next();
  };
}
```

**Equivalente NestJS (Roles Guard)**:

```typescript
// src/common/decorators/roles.decorator.ts
import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
```

```typescript
// src/common/guards/roles.guard.ts
import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    
    if (!requiredRoles) {
      return true;
    }
    
    const { user } = context.switchToHttp().getRequest();
    
    if (!user) {
      throw new ForbiddenException('User not found in request');
    }
    
    const hasRole = requiredRoles.some((role) => user.role === role);
    
    if (!hasRole) {
      throw new ForbiddenException('Forbidden: Administrator access required');
    }
    
    return true;
  }
}
```

---

## 4. Controladores

### AuthController

**Archivo**: `src/presentation/auth/controller.ts`

```typescript
import { Request, Response } from 'express';
import { CustomError } from '../../domain/errors';
import { LoginDto, RegisterDto } from '../../domain/dtos/auth';
import { AuthRepository } from '../../domain/repositories';
import { Renew } from '../../domain/use-cases/auth/renew.use-case';
import { RegisterUser } from '../../domain/use-cases/auth/register.use-case';
import { LoginUser } from '../../domain/use-cases/auth';

export class AuthController {

    constructor(private readonly authRepository: AuthRepository) {}

    private handleError = (error: unknown, res: Response) => {
        if (error instanceof CustomError) {
            return res.status(error.statusCode).json({ error, message: error.message, status: false })
        }

        return res.status(500).json({
            error: 'Internal Server Error'
        })
    }

    login = (req: Request, res: Response) => {
        const { role } = req.params;
        const [error, loginUserDto] = LoginDto.create({ ...req.body, role });
        if (error) return res.status(400).json({ error });
        new LoginUser(this.authRepository)
            .execute(loginUserDto!)
            .then(data => res.json(data))
            .catch(error => this.handleError(error, res));
    }

    register = (req: Request, res: Response) => {
        const { role } = req.params;
        const [error, registerDto] = RegisterDto.create({...req.body, role });
        if (error) return res.status(400).json({ error });
        new RegisterUser(this.authRepository)
          .execute(registerDto!)
          .then(data => res.json(data))
          .catch(error => this.handleError(error, res));
    }

    renew = (req: Request, res: Response) => {
        new Renew()
            .execute({ ...req.body.user })
            .then(data => res.json(data))
            .catch(error => this.handleError(error, res));
    }
}
```

**Equivalente NestJS**:

```typescript
// src/modules/auth/auth.controller.ts
import { Controller, Post, Body, Param, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login/:role')
  async login(
    @Body() loginDto: LoginDto,
    @Param('role') role: string,
  ) {
    return this.authService.login({ ...loginDto, role });
  }

  @Post('register/:role')
  async register(
    @Body() registerDto: RegisterDto,
    @Param('role') role: string,
  ) {
    return this.authService.register({ ...registerDto, role });
  }

  @Post('renew')
  @UseGuards(JwtAuthGuard)
  async renew(@Request() req) {
    return this.authService.renew(req.user);
  }
}
```

### AuthRoutes

**Archivo**: `src/presentation/auth/routes.ts`

```typescript
import { Router } from "express";
import { AuthDatasourceImpl } from "../../infrastructure/datasources";
import { AuthRepositoryImpl } from "../../infrastructure/repositories";
import { AuthController } from "./controller";
import { AuthMiddleware } from "../middlewares";

export class AuthRoutes {

    static get routes(): Router {

        const router = Router();

        const authDataSource = new AuthDatasourceImpl();
        const authRepository = new AuthRepositoryImpl(authDataSource);
        const controller = new AuthController(authRepository);

        router.post('/login/:role', controller.login);
        router.post('/register/:role', controller.register);
        router.post('/renew', [AuthMiddleware.validateJwt], controller.renew);

        return router;
    }
}
```

**Equivalente NestJS (auth.module.ts)**:

```typescript
// src/modules/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { User } from '../../database/entities/user.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_SEED'),
        signOptions: { expiresIn: '4h' },
      }),
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
  exports: [JwtStrategy, PassportModule, JwtModule],
})
export class AuthModule {}
```

---

### UserController

**Archivo**: `src/presentation/user/controller.ts`

```typescript
import { Request, Response } from 'express';
import { CustomError } from '../../domain/errors';
import { UserRepository } from '../../domain/repositories';
import { UpdateUserDto, UpdateUserByAdminDto } from '../../domain/dtos/user';
import { GetAllUsers, GetUser, UpdateUser, UpdateUserByAdmin, DeleteUser } from '../../domain/use-cases/user';
import { UserEntity } from '../../domain/entities';

export class UserController {

    constructor(private readonly userRepository: UserRepository) {}

    private handleError = (error: unknown, res: Response) => {
        if (error instanceof CustomError) {
            return res.status(error.statusCode).json({ error: error.message });
        }
        console.log(error);
        return res.status(500).json({ error: 'Internal Server Error' });
    }

    // GET /api/users
    getAllUsers = (req: Request, res: Response) => {
        new GetAllUsers(this.userRepository)
            .execute()
            .then(users => res.json(users.map(user => {
                const { password, ...rest } = user;
                return rest;
            })))
            .catch(error => this.handleError(error, res));
    }

    // GET /api/users/profile
    getUserProfile = (req: Request, res: Response) => {
        const user: UserEntity = req.body.user;
        new GetUser(this.userRepository)
            .execute(user.uid)
            .then(userProfile => {
                const { password, ...rest } = userProfile;
                res.json(rest);
            })
            .catch(error => this.handleError(error, res));
    }

    // PUT /api/users/profile
    updateUserProfile = (req: Request, res: Response) => {
        const user: UserEntity = req.body.user;
        const [error, updateUserDto] = UpdateUserDto.create({ ...req.body, uid: user.uid });
        if (error) return res.status(400).json({ error });

        new UpdateUser(this.userRepository)
            .execute(updateUserDto!)
            .then(updatedUser => {
                const { password, ...rest } = updatedUser;
                res.json(rest);
            })
            .catch(error => this.handleError(error, res));
    }

    // DELETE /api/users/profile
    deleteUserProfile = (req: Request, res: Response) => {
        const user: UserEntity = req.body.user;
        new DeleteUser(this.userRepository)
            .execute(user.uid)
            .then(deletedUser => res.json({ message: 'User profile deactivated successfully', user: { uid: deletedUser.uid } }))
            .catch(error => this.handleError(error, res));
    }

    // PUT /api/users/:uid
    updateUserByAdmin = (req: Request, res: Response) => {
        const { uid: targetUid } = req.params;
        const [error, updateUserByAdminDto] = UpdateUserByAdminDto.create({ ...req.body, targetUid });
        if (error) return res.status(400).json({ error });

        new UpdateUserByAdmin(this.userRepository)
            .execute(updateUserByAdminDto!)
            .then(updatedUser => {
                const { password, ...rest } = updatedUser;
                res.json(rest);
            })
            .catch(error => this.handleError(error, res));
    }
}
```

**Equivalente NestJS**:

```typescript
// src/modules/user/user.controller.ts
import { 
  Controller, Get, Put, Delete, Body, Param, 
  UseGuards, Request 
} from '@nestjs/common';
import { UserService } from './user.service';
import { UpdateUserDto } from './dto/update-user.dto';
import { UpdateUserByAdminDto } from './dto/update-user-admin.dto';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { GetUser } from '../../common/decorators/get-user.decorator';
import { User } from '../../database/entities/user.entity';

@Controller('users')
@UseGuards(JwtAuthGuard)
export class UserController {
  constructor(private readonly userService: UserService) {}

  // GET /api/users/profile
  @Get('profile')
  async getUserProfile(@GetUser() user: User) {
    return this.userService.findById(user.uid);
  }

  // PUT /api/users/profile
  @Put('profile')
  async updateUserProfile(
    @GetUser() user: User,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    return this.userService.updateUser({ ...updateUserDto, uid: user.uid });
  }

  // DELETE /api/users/profile
  @Delete('profile')
  async deleteUserProfile(@GetUser() user: User) {
    return this.userService.deleteUser(user.uid);
  }

  // GET /api/users (Admin only)
  @Get()
  @UseGuards(RolesGuard)
  @Roles('admin')
  async getAllUsers() {
    return this.userService.findAll();
  }

  // PUT /api/users/:uid (Admin only)
  @Put(':uid')
  @UseGuards(RolesGuard)
  @Roles('admin')
  async updateUserByAdmin(
    @Param('uid') targetUid: string,
    @Body() updateUserByAdminDto: UpdateUserByAdminDto,
  ) {
    return this.userService.updateUserByAdmin({ ...updateUserByAdminDto, targetUid });
  }
}
```

---

### UserRoutes

**Archivo**: `src/presentation/user/routes.ts`

```typescript
import { Router } from "express";
import { UserDatasourceImpl } from "../../infrastructure/datasources/user.datasource.impl";
import { UserRepositoryImpl } from "../../infrastructure/repositories/user.repository.impl";
import { UserController } from "./controller";
import { AuthMiddleware, RoleMiddleware } from "../middlewares";

export class UserRoutes {

    static get routes(): Router {
        const router = Router();
        const userDatasource = new UserDatasourceImpl();
        const userRepository = new UserRepositoryImpl(userDatasource);
        const controller = new UserController(userRepository);

        // All routes below require authentication
        router.use(AuthMiddleware.validateJwt);

        // Profile routes (for the authenticated user)
        router.get('/profile', controller.getUserProfile);
        router.put('/profile', controller.updateUserProfile);
        router.delete('/profile', controller.deleteUserProfile);

        // Admin routes (require admin role)
        router.get('/', RoleMiddleware.isAdmin, controller.getAllUsers);
        router.put('/:uid', RoleMiddleware.isAdmin, controller.updateUserByAdmin);

        return router;
    }
}
```

**Equivalente NestJS (user.module.ts)**:

```typescript
// src/modules/user/user.module.ts
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserController } from './user.controller';
import { UserService } from './user.service';
import { User } from '../../database/entities/user.entity';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    AuthModule,
  ],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService],
})
export class UserModule {}
```

---

## 5. Decorador GetUser (NestJS)

```typescript
// src/common/decorators/get-user.decorator.ts
import { createParamDecorator, ExecutionContext, InternalServerErrorException } from '@nestjs/common';

export const GetUser = createParamDecorator(
  (data: string, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    if (!user) {
      throw new InternalServerErrorException('User not found in request');
    }

    return data ? user[data] : user;
  },
);
```
