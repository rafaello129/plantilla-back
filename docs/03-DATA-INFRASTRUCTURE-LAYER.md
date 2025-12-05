# Capa de Datos e Infraestructura

Esta sección documenta la capa de persistencia y las implementaciones de infraestructura.

---

## 1. Entidad TypeORM (Modelo de Base de Datos)

### User Entity

**Archivo**: `src/data/postgres/entities/user.entity.ts`

```typescript
import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn, UpdateDateColumn } from "typeorm";

@Entity('users')
export class User {
    
    @PrimaryGeneratedColumn('uuid')
    uid: string;

    @Column({ type: 'varchar' })
    name: string;

    @Column({ type: 'varchar', default: 'user' })
    role: string;

    @Column({ type: 'varchar', unique: true })
    username: string;

    @Column({ type: 'varchar', unique: true })
    email: string;
  
    @Column({ type: 'varchar', unique: true, nullable: true })
    phone: string;

    @Column({ type: 'varchar' })
    password?: string;

    @Column({ type: 'varchar', nullable: true })
    picture: string;

    @Column({ type: 'bool', default: true })
    is_active: boolean;

    @Column({ type: 'bool', default: false })
    is_online: boolean;

    @Column({ type: 'bool', default: false })
    is_disabled: boolean;

    @Column({ type: 'bool', default: false })
    is_google: boolean;
  
    @CreateDateColumn({ 
        type: "timestamp", 
        default: () => "CURRENT_TIMESTAMP(6)" 
    })
    created_at: Date;

    @UpdateDateColumn({ 
        type: "timestamp", 
        default: () => "CURRENT_TIMESTAMP(6)", 
        onUpdate: "CURRENT_TIMESTAMP(6)"
    })
    updated_at: Date;
}
```

**Equivalente NestJS (mismo código, solo ubicación diferente)**:

En NestJS, esta entidad se ubicaría en `src/database/entities/user.entity.ts` o directamente en `src/modules/user/entities/user.entity.ts`.

---

## 2. Conexión a Base de Datos

### PostgresDatabase

**Archivo**: `src/data/postgres/postgres-database.ts`

```typescript
import { DataSource, Connection } from "typeorm";
import { User } from "./entities";

interface Options {
    host: string;
    port: number;
    username: string;
    password: string;
    database: string;
}

export class PostgresDatabase {
    static dataSource: DataSource;

    static async connect(options: Options): Promise<Connection> {

        console.log({
            host: options.host,
            port: options.port,
            username: options.username,
            password: options.password,
            database: options.database,
        });

        this.dataSource = new DataSource({
            type: "postgres",
            host: options.host,
            port: options.port,
            username: options.username,
            password: options.password,
            database: options.database,
            synchronize: true, // Solo para desarrollo
            entities: [User],
            extra: {
                max: 10, 
            },
        });

        return this.initializeConnection();
    }

    private static async initializeConnection(): Promise<Connection> {
        const maxRetries = 5;
        let attempt = 0;

        while (attempt < maxRetries) {
            try {
                const connection = await this.dataSource.initialize();
                console.log('Database connected successfully');
                return connection;
            } catch (error) {
                attempt++;
                console.error(`Error connecting to database (attempt ${attempt}):`, error);

                if (attempt < maxRetries) {
                    console.log("Retrying in 5 seconds...");
                    await this.delay(5000);
                } else {
                    throw new Error("Failed to connect to the database after multiple attempts");
                }
            }
        }

        throw new Error("Unexpected error during database connection");
    }

    private static delay(ms: number): Promise<void> {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }
}
```

**Equivalente NestJS con @nestjs/typeorm**:

```typescript
// src/database/database.module.ts
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { User } from './entities/user.entity';

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        host: configService.get('HOST_DB'),
        port: configService.get('PORT_DB'),
        username: configService.get('USERNAME_DB'),
        password: configService.get('PASSWORD_DB'),
        database: configService.get('DATABASE_DB'),
        entities: [User],
        synchronize: true, // Solo para desarrollo
        retryAttempts: 5,
        retryDelay: 5000,
        extra: {
          max: 10,
        },
      }),
    }),
  ],
})
export class DatabaseModule {}
```

---

## 3. Mapper

### UserMapper

**Archivo**: `src/infrastructure/mappers/user.mapper.ts`

```typescript
import { UserEntity } from "../../domain/entities";
import { CustomError } from "../../domain/errors";

export class UserMapper {

    static userEntityFromObject(obj: { [key: string]: any }) {

        const { 
            uid,
            name,
            username,
            email,
            phone,
            password,
            picture,
            is_active,
            is_online,
            is_disabled,
            is_google,
            created_at,
            updated_at,
            role,
        } = obj;

        if (!uid) throw CustomError.badRequest(`'uid' is missing`);
        if (!username) throw CustomError.badRequest(`'username' is missing`);
        if (!password) throw CustomError.badRequest(`'password' is missing`);

        return new UserEntity(
            uid,
            name,
            username,
            email,
            phone,
            password,
            picture,
            is_active,
            is_online,
            is_disabled,
            is_google,
            created_at,
            updated_at,
            role,
        );
    }
}
```

**En NestJS**: El mapper puede mantenerse igual o usar `class-transformer` con `plainToClass()`.

---

## 4. Implementaciones de Datasources

### AuthDatasourceImpl

**Archivo**: `src/infrastructure/datasources/auth.datasource.impl.ts`

```typescript
import { Not, QueryRunner } from "typeorm";
import { BcryptAdapter } from "../../config";
import { PostgresDatabase } from "../../data/postgres";
import { User } from "../../data/postgres/entities/user.entity";
import { AuthDatasource } from "../../domain/datasources";
import { LoginDto, RegisterDto } from "../../domain/dtos/auth";
import { UserEntity } from "../../domain/entities";
import { CustomError } from "../../domain/errors";
import { UserMapper } from "../mappers";

type HashFunction = (password: string) => string;
type CompareFunction = (password: string, hashed: string) => boolean;

export class AuthDatasourceImpl implements AuthDatasource {
    
    constructor(
        private readonly hashPassword: HashFunction = BcryptAdapter.hash,
        private readonly comparePassword: CompareFunction = BcryptAdapter.compare,
    ) {}
  
    async login(loginDto: LoginDto): Promise<UserEntity> {
        const { username, password } = loginDto;
        const queryRunner = PostgresDatabase.dataSource.createQueryRunner();

        await queryRunner.connect();

        try {
            const user = await this.findUser(queryRunner, username);

            if (!user) {
                throw CustomError.badRequest(`Credenciales incorrectas.`);
            }

            this.validatePassword(password, user.password!);

            return UserMapper.userEntityFromObject({ ...user });
        } catch (error) {
            if (error instanceof CustomError) throw error;
            throw CustomError.internalServer();
        } finally {
            await queryRunner.release();
        }
    }

    private async findUser(queryRunner: QueryRunner, username: string) {
        return await queryRunner.manager.findOne(User, {
            where: [
                { username: username.toLowerCase(), is_active: true },
                { email: username.toLowerCase(), is_active: true },
            ],
            select: {
                uid: true,
                username: true,
                email: true,
                phone: true,
                password: true,
                is_active: true,
                is_online: true,
                is_disabled: true,
                is_google: true,
                created_at: true,
                updated_at: true,
                picture: true,
                role: true,
            }
        });
    }

    private validatePassword(password: string, hashedPassword: string) {
        const isMatching = this.comparePassword(password, hashedPassword);
        if (!isMatching) {
            throw CustomError.badRequest('Credenciales incorrectas.');
        }
    }

    async register(registerUserDto: RegisterDto): Promise<UserEntity> {
        const { name, username, password, role } = registerUserDto;
        const queryRunner = PostgresDatabase.dataSource.createQueryRunner();

        await queryRunner.connect();

        try {
            await queryRunner.startTransaction();

            const userdb = await queryRunner.manager.findOne(User, {
                where: [
                    { username: username.toLowerCase() },
                    { email: username.toLowerCase() }
                ],
            });

            if (userdb) {
                throw CustomError.badRequest(
                    `Ya existe un usuario con el username '${username.toLowerCase()}'`
                );
            }

            const user = queryRunner.manager.create(User, {
                name,
                username,
                role,
                email: username,
                password: this.hashPassword(password),
            });

            await queryRunner.manager.save(user);
            await queryRunner.commitTransaction();

            return UserMapper.userEntityFromObject({ ...user });
        } catch (error) {
            console.log(error);
            await queryRunner.rollbackTransaction();
            if (error instanceof CustomError) throw error;
            throw CustomError.internalServer();
        } finally {
            await queryRunner.release();
        }
    }
}
```

**Equivalente NestJS (como servicio inyectable)**:

```typescript
// src/modules/auth/services/auth-datasource.service.ts
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { User } from '../../../database/entities/user.entity';
import { LoginDto } from '../dto/login.dto';
import { RegisterDto } from '../dto/register.dto';
import { UserEntity } from '../../../domain/entities/user.entity';
import { CustomException } from '../../../common/exceptions/custom.exception';
import { UserMapper } from '../../../common/mappers/user.mapper';

@Injectable()
export class AuthDatasourceService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly dataSource: DataSource,
  ) {}

  async login(loginDto: LoginDto): Promise<UserEntity> {
    const { username, password } = loginDto;
    
    const user = await this.userRepository.findOne({
      where: [
        { username: username.toLowerCase(), is_active: true },
        { email: username.toLowerCase(), is_active: true },
      ],
      select: {
        uid: true, username: true, email: true, phone: true,
        password: true, is_active: true, is_online: true,
        is_disabled: true, is_google: true, created_at: true,
        updated_at: true, picture: true, role: true,
      }
    });

    if (!user) {
      throw CustomException.badRequest('Credenciales incorrectas.');
    }

    const isMatching = bcrypt.compareSync(password, user.password!);
    if (!isMatching) {
      throw CustomException.badRequest('Credenciales incorrectas.');
    }

    return UserMapper.userEntityFromObject({ ...user });
  }

  async register(registerDto: RegisterDto): Promise<UserEntity> {
    const { name, username, password, role } = registerDto;
    
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const existingUser = await queryRunner.manager.findOne(User, {
        where: [
          { username: username.toLowerCase() },
          { email: username.toLowerCase() }
        ],
      });

      if (existingUser) {
        throw CustomException.badRequest(
          `Ya existe un usuario con el username '${username.toLowerCase()}'`
        );
      }

      const user = queryRunner.manager.create(User, {
        name,
        username: username.toLowerCase(),
        role,
        email: username.toLowerCase(),
        password: bcrypt.hashSync(password, 10),
      });

      await queryRunner.manager.save(user);
      await queryRunner.commitTransaction();

      return UserMapper.userEntityFromObject({ ...user });
    } catch (error) {
      await queryRunner.rollbackTransaction();
      if (error instanceof CustomException) throw error;
      throw CustomException.internalServer();
    } finally {
      await queryRunner.release();
    }
  }
}
```

---

### UserDatasourceImpl

**Archivo**: `src/infrastructure/datasources/user.datasource.impl.ts`

```typescript
import { PostgresDatabase } from "../../data/postgres";
import { User } from "../../data/postgres/entities";
import { UserDatasource } from "../../domain/datasources/user.datasource";
import { UpdateUserByAdminDto, UpdateUserDto } from "../../domain/dtos/user";
import { UserEntity } from "../../domain/entities";
import { CustomError } from "../../domain/errors";
import { UserMapper } from "../mappers";

export class UserDatasourceImpl implements UserDatasource {

    async findById(uid: string): Promise<UserEntity> {
        const queryRunner = PostgresDatabase.dataSource.createQueryRunner();
        await queryRunner.connect();
        try {
            const user = await queryRunner.manager.findOne(User, { where: { uid } });
            if (!user) throw CustomError.notFound('User not found');
            return UserMapper.userEntityFromObject(user);
        } catch (error) {
            if (error instanceof CustomError) throw error;
            throw CustomError.internalServer();
        } finally {
            await queryRunner.release();
        }
    }

    async findAll(): Promise<UserEntity[]> {
        const queryRunner = PostgresDatabase.dataSource.createQueryRunner();
        await queryRunner.connect();
        try {
            const users = await queryRunner.manager.find(User);
            return users.map(UserMapper.userEntityFromObject);
        } catch (error) {
            throw CustomError.internalServer();
        } finally {
            await queryRunner.release();
        }
    }

    async updateUser(updateUserDto: UpdateUserDto): Promise<UserEntity> {
        const queryRunner = PostgresDatabase.dataSource.createQueryRunner();
        await queryRunner.connect();
        await queryRunner.startTransaction();
        try {
            const user = await queryRunner.manager.findOne(User, { where: { uid: updateUserDto.uid } });
            if (!user) throw CustomError.notFound('User not found');

            const { name, email, phone, picture } = updateUserDto;
            if (name) user.name = name;
            if (email) user.email = email;
            if (phone) user.phone = phone;
            if (picture) user.picture = picture;

            const updatedUser = await queryRunner.manager.save(user);
            await queryRunner.commitTransaction();

            return UserMapper.userEntityFromObject(updatedUser);
        } catch (error: any) {  
            await queryRunner.rollbackTransaction();
            if (error.code === '23505') { // Unique constraint violation
                throw CustomError.conflict('Email or phone already exists');
            }
            if (error instanceof CustomError) throw error;
            throw CustomError.internalServer();
        } finally {
            await queryRunner.release();
        }
    }

    async updateUserByAdmin(updateUserByAdminDto: UpdateUserByAdminDto): Promise<UserEntity> {
        const queryRunner = PostgresDatabase.dataSource.createQueryRunner();
        await queryRunner.connect();
        await queryRunner.startTransaction();
        try {
            const { targetUid, role, is_active, is_disabled } = updateUserByAdminDto;
            const user = await queryRunner.manager.findOne(User, { where: { uid: targetUid } });
            if (!user) throw CustomError.notFound('User not found');

            if (role) user.role = role;
            if (is_active !== undefined) user.is_active = is_active;
            if (is_disabled !== undefined) user.is_disabled = is_disabled;

            const updatedUser = await queryRunner.manager.save(user);
            await queryRunner.commitTransaction();

            return UserMapper.userEntityFromObject(updatedUser);
        } catch (error) {
            await queryRunner.rollbackTransaction();
            if (error instanceof CustomError) throw error;
            throw CustomError.internalServer();
        } finally {
            await queryRunner.release();
        }
    }

    async deleteUser(uid: string): Promise<UserEntity> {
        const queryRunner = PostgresDatabase.dataSource.createQueryRunner();
        await queryRunner.connect();
        await queryRunner.startTransaction();
        try {
            const user = await queryRunner.manager.findOne(User, { where: { uid } });
            if (!user) throw CustomError.notFound('User not found');

            // Soft delete by deactivating the user
            user.is_active = false;
            const deletedUser = await queryRunner.manager.save(user);
            await queryRunner.commitTransaction();

            return UserMapper.userEntityFromObject(deletedUser);
        } catch (error) {
            await queryRunner.rollbackTransaction();
            if (error instanceof CustomError) throw error;
            throw CustomError.internalServer();
        } finally {
            await queryRunner.release();
        }
    }
}
```

---

## 5. Implementaciones de Repositorios

### AuthRepositoryImpl

**Archivo**: `src/infrastructure/repositories/auth.repository.impl.ts`

```typescript
import { AuthDatasource } from "../../domain/datasources";
import { LoginDto, RegisterDto } from "../../domain/dtos/auth";
import { UserEntity } from "../../domain/entities";
import { AuthRepository } from "../../domain/repositories";

export class AuthRepositoryImpl implements AuthRepository {
    
    constructor(private readonly dataSource: AuthDatasource) {}

    register(registerDto: RegisterDto): Promise<UserEntity> {
        return this.dataSource.register(registerDto);
    }

    login(loginDto: LoginDto): Promise<UserEntity> {
        return this.dataSource.login(loginDto);
    }
}
```

### UserRepositoryImpl

**Archivo**: `src/infrastructure/repositories/user.repository.impl.ts`

```typescript
import { UserDatasource } from "../../domain/datasources/user.datasource";
import { UpdateUserByAdminDto, UpdateUserDto } from "../../domain/dtos/user";
import { UserEntity } from "../../domain/entities";
import { UserRepository } from "../../domain/repositories/user.repository";

export class UserRepositoryImpl implements UserRepository {
    
    constructor(private readonly userDatasource: UserDatasource) {}

    findById(uid: string): Promise<UserEntity> {
        return this.userDatasource.findById(uid);
    }
    
    findAll(): Promise<UserEntity[]> {
        return this.userDatasource.findAll();
    }

    updateUser(updateUserDto: UpdateUserDto): Promise<UserEntity> {
        return this.userDatasource.updateUser(updateUserDto);
    }
    
    updateUserByAdmin(updateUserByAdminDto: UpdateUserByAdminDto): Promise<UserEntity> {
        return this.userDatasource.updateUserByAdmin(updateUserByAdminDto);
    }

    deleteUser(uid: string): Promise<UserEntity> {
        return this.userDatasource.deleteUser(uid);
    }
}
```

---

## 6. Notas para la Migración a NestJS

### Patrón Repository en NestJS

En NestJS puedes simplificar usando directamente el repositorio de TypeORM:

```typescript
// src/modules/user/user.service.ts
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../database/entities/user.entity';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async findById(uid: string): Promise<User> {
    const user = await this.userRepository.findOne({ where: { uid } });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  async findAll(): Promise<User[]> {
    return this.userRepository.find();
  }
}
```

### Transacciones en NestJS

```typescript
import { DataSource } from 'typeorm';

@Injectable()
export class UserService {
  constructor(private readonly dataSource: DataSource) {}

  async updateWithTransaction(dto: UpdateDto): Promise<User> {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();
    
    try {
      // operaciones
      await queryRunner.commitTransaction();
      return result;
    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }
}
```
