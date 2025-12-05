# Capa de Dominio (Domain Layer)

La capa de dominio contiene la lógica de negocio pura y no depende de ningún framework.

---

## 1. Entidades de Dominio

### UserEntity

**Archivo Original**: `src/domain/entities/user.entity.ts`

```typescript
export class UserEntity {
    constructor(
        public uid: string,
        public name: string,
        public username: string,
        public email: string,
        public phone: string,
        public password: string,
        public picture: string,
        public is_active: boolean,
        public is_online: boolean,
        public is_disabled: boolean,
        public is_google: boolean,
        public created_at: Date,
        public updated_at: Date,
        public role: string,
    ) {}
}
```

### Propiedades de Usuario

| Campo | Tipo | Descripción |
|-------|------|-------------|
| uid | string (UUID) | Identificador único del usuario |
| name | string | Nombre completo |
| username | string | Nombre de usuario (único) |
| email | string | Correo electrónico (único) |
| phone | string | Teléfono (único, opcional) |
| password | string | Contraseña hasheada |
| picture | string | URL de foto de perfil (opcional) |
| is_active | boolean | Usuario activo (soft delete) |
| is_online | boolean | Estado de conexión |
| is_disabled | boolean | Usuario deshabilitado por admin |
| is_google | boolean | Autenticación por Google |
| role | string | Rol: 'user' o 'admin' |
| created_at | Date | Fecha de creación |
| updated_at | Date | Fecha de actualización |

---

## 2. DTOs (Data Transfer Objects)

Los DTOs usan un patrón de validación estático con factory method `create()`.

### LoginDto

**Archivo**: `src/domain/dtos/auth/login.dto.ts`

```typescript
export class LoginDto {
    private constructor(
        public username: string,
        public password: string,
    ) {}

    static create(object: { [key: string]: any }): [string?, LoginDto?] {
        const { username, password } = object;

        if (!username) return [`Missing 'username'`];
        if (!password) return [`Missing 'password'`];
        if (password.length < 6) return [`'password' too short, min length 6`];

        return [undefined, new LoginDto(username.toLowerCase(), password)];
    }
}
```

**Equivalente NestJS con class-validator**:

```typescript
import { IsString, MinLength, IsNotEmpty } from 'class-validator';
import { Transform } from 'class-transformer';

export class LoginDto {
    @IsString()
    @IsNotEmpty({ message: "Missing 'username'" })
    @Transform(({ value }) => value?.toLowerCase())
    username: string;

    @IsString()
    @IsNotEmpty({ message: "Missing 'password'" })
    @MinLength(6, { message: "'password' too short, min length 6" })
    password: string;
}
```

### RegisterDto

**Archivo**: `src/domain/dtos/auth/register.dto.ts`

```typescript
export class RegisterDto {
    private constructor(
        public name: string,
        public username: string,
        public password: string,
        public role: string = 'user',
    ) {}

    static create(object: { [key: string]: any }): [string?, RegisterDto?] {
        const { name, username, password, role } = object;

        if (!name) return [`Missing 'name'`];
        if (!username) return [`Missing 'username'`];
        if (!password) return [`Missing 'password'`];
        if (role !== 'user' && role !== 'admin') return [`Invalid 'role', must be 'user' or 'admin'`];
        if (password.length < 6) return [`'password' too short, min length 6`];

        return [undefined, new RegisterDto(name, username.toLowerCase(), password, role)];
    }
}
```

**Equivalente NestJS con class-validator**:

```typescript
import { IsString, MinLength, IsNotEmpty, IsIn, IsOptional } from 'class-validator';
import { Transform } from 'class-transformer';

export class RegisterDto {
    @IsString()
    @IsNotEmpty({ message: "Missing 'name'" })
    name: string;

    @IsString()
    @IsNotEmpty({ message: "Missing 'username'" })
    @Transform(({ value }) => value?.toLowerCase())
    username: string;

    @IsString()
    @IsNotEmpty({ message: "Missing 'password'" })
    @MinLength(6, { message: "'password' too short, min length 6" })
    password: string;

    @IsOptional()
    @IsIn(['user', 'admin'], { message: "Invalid 'role', must be 'user' or 'admin'" })
    role: string = 'user';
}
```

### UpdateUserDto

**Archivo**: `src/domain/dtos/user/update-user.dto.ts`

```typescript
import { Validators } from "../../../config";

export class UpdateUserDto {
    private constructor(
        public uid: string,
        public name?: string,
        public email?: string,
        public phone?: string,
        public picture?: string,
    ) {}

    static create(object: { [key: string]: any }): [string?, UpdateUserDto?] {
        const { uid, name, email, phone, picture } = object;

        if (!uid) return [`Missing 'uid'`];

        if (email && !Validators.email.test(email)) {
            return [`Invalid 'email'`];
        }

        return [undefined, new UpdateUserDto(uid, name, email, phone, picture)];
    }
}
```

**Equivalente NestJS con class-validator**:

```typescript
import { IsString, IsEmail, IsOptional, IsUUID } from 'class-validator';

export class UpdateUserDto {
    @IsUUID()
    @IsOptional() // El uid se obtiene del token JWT, no del body
    uid?: string;

    @IsString()
    @IsOptional()
    name?: string;

    @IsEmail({}, { message: "Invalid 'email'" })
    @IsOptional()
    email?: string;

    @IsString()
    @IsOptional()
    phone?: string;

    @IsString()
    @IsOptional()
    picture?: string;
}
```

### UpdateUserByAdminDto

**Archivo**: `src/domain/dtos/user/update-user-admin.dto.ts`

```typescript
export class UpdateUserByAdminDto {
    private constructor(
        public targetUid: string,
        public role?: string,
        public is_active?: boolean,
        public is_disabled?: boolean,
    ) {}

    static create(object: { [key: string]: any }): [string?, UpdateUserByAdminDto?] {
        const { targetUid, role, is_active, is_disabled } = object;

        if (!targetUid) return [`Missing 'targetUid'`];

        if (role && role !== 'user' && role !== 'admin') {
            return [`Invalid 'role', must be 'user' or 'admin'`];
        }
        
        if (is_active !== undefined && typeof is_active !== 'boolean') {
            return [`'is_active' must be a boolean`];
        }

        if (is_disabled !== undefined && typeof is_disabled !== 'boolean') {
            return [`'is_disabled' must be a boolean`];
        }

        return [undefined, new UpdateUserByAdminDto(targetUid, role, is_active, is_disabled)];
    }
}
```

**Equivalente NestJS con class-validator**:

```typescript
import { IsString, IsOptional, IsIn, IsBoolean, IsUUID } from 'class-validator';

export class UpdateUserByAdminDto {
    @IsUUID()
    @IsOptional() // El targetUid viene del path param
    targetUid?: string;

    @IsIn(['user', 'admin'], { message: "Invalid 'role', must be 'user' or 'admin'" })
    @IsOptional()
    role?: string;

    @IsBoolean({ message: "'is_active' must be a boolean" })
    @IsOptional()
    is_active?: boolean;

    @IsBoolean({ message: "'is_disabled' must be a boolean" })
    @IsOptional()
    is_disabled?: boolean;
}
```

---

## 3. Datasources Abstractos

Los datasources definen los contratos para acceso a datos. Son interfaces abstractas.

### AuthDatasource

**Archivo**: `src/domain/datasources/auth.datasource.ts`

```typescript
import { LoginDto, RegisterDto } from "../dtos/auth";
import { UserEntity } from "../entities";

export abstract class AuthDatasource {
    abstract login(loginDto: LoginDto): Promise<UserEntity>
    abstract renew?(): Promise<UserEntity>
    abstract register(registerDto: RegisterDto): Promise<UserEntity>
}
```

### UserDatasource

**Archivo**: `src/domain/datasources/user.datasource.ts`

```typescript
import { UpdateUserByAdminDto, UpdateUserDto } from "../dtos/user";
import { UserEntity } from "../entities";

export abstract class UserDatasource {
    abstract findById(uid: string): Promise<UserEntity>;
    abstract findAll(): Promise<UserEntity[]>;
    abstract updateUser(updateUserDto: UpdateUserDto): Promise<UserEntity>;
    abstract updateUserByAdmin(updateUserByAdminDto: UpdateUserByAdminDto): Promise<UserEntity>;
    abstract deleteUser(uid: string): Promise<UserEntity>;
}
```

---

## 4. Repositorios Abstractos

Los repositorios son la abstracción de alto nivel para acceso a datos.

### AuthRepository

**Archivo**: `src/domain/repositories/auth.repository.ts`

```typescript
import { LoginDto, RegisterDto } from "../dtos/auth";
import { UserEntity } from "../entities";

export abstract class AuthRepository {
    abstract login(loginDto: LoginDto): Promise<UserEntity>
    abstract renew?(): Promise<UserEntity>
    abstract register(registerDto: RegisterDto): Promise<UserEntity>
}
```

### UserRepository

**Archivo**: `src/domain/repositories/user.repository.ts`

```typescript
import { UpdateUserByAdminDto, UpdateUserDto } from "../dtos/user";
import { UserEntity } from "../entities";

export abstract class UserRepository {
    abstract findById(uid: string): Promise<UserEntity>;
    abstract findAll(): Promise<UserEntity[]>;
    abstract updateUser(updateUserDto: UpdateUserDto): Promise<UserEntity>;
    abstract updateUserByAdmin(updateUserByAdminDto: UpdateUserByAdminDto): Promise<UserEntity>;
    abstract deleteUser(uid: string): Promise<UserEntity>;
}
```

---

## 5. Manejo de Errores

### CustomError

**Archivo**: `src/domain/errors/custom.error.ts`

```typescript
export class CustomError extends Error {
    constructor(
        public readonly statusCode: number,
        public readonly message: string
    ){
        super(message);
    }

    static badRequest(message: string) {
        return new CustomError(400, message);
    }

    static unauthorized(message: string) {
        return new CustomError(401, message);
    }

    static forbidden(message: string) {
        return new CustomError(403, message);
    }

    static notFound(message: string) {
        return new CustomError(404, message);
    }

    static conflict(message: string): CustomError {
        return new CustomError(409, message);
    }

    static internalServer(message: string = 'Internal Server Error') {
        console.log(message);
        return new CustomError(500, message);
    }
}
```

**Equivalente NestJS con HttpException**:

```typescript
import { HttpException, HttpStatus } from '@nestjs/common';

export class CustomException extends HttpException {
    constructor(message: string, statusCode: number) {
        super(message, statusCode);
    }

    static badRequest(message: string) {
        return new CustomException(message, HttpStatus.BAD_REQUEST);
    }

    static unauthorized(message: string) {
        return new CustomException(message, HttpStatus.UNAUTHORIZED);
    }

    static forbidden(message: string) {
        return new CustomException(message, HttpStatus.FORBIDDEN);
    }

    static notFound(message: string) {
        return new CustomException(message, HttpStatus.NOT_FOUND);
    }

    static conflict(message: string) {
        return new CustomException(message, HttpStatus.CONFLICT);
    }

    static internalServer(message: string = 'Internal Server Error') {
        console.log(message);
        return new CustomException(message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
```
