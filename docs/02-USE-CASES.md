# Casos de Uso (Use Cases)

Los casos de uso encapsulan la lógica de negocio y orquestan las operaciones entre repositorios.

---

## 1. Casos de Uso de Autenticación

### LoginUser UseCase

**Archivo**: `src/domain/use-cases/auth/login.use-case.ts`

```typescript
import { JwtAdapter } from "../../../config";
import { LoginDto } from "../../dtos/auth";
import { CustomError } from "../../errors";
import { AuthRepository } from "../../repositories";

interface UserAccessToken {
  status: boolean;
  accessToken: string;
  user: {
    uid: string;
    username: string;
    is_online: boolean;
    role: string;
    picture?: string;
    profile?: any;
  };
}

type SignToken = (payload: Object, duration?: number) => Promise<string | null>;

interface LoginUserUseCase {
  execute(loginUserDto: LoginDto): Promise<UserAccessToken>;
}

export class LoginUser implements LoginUserUseCase {
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly signToken: SignToken = JwtAdapter.generateToken,
  ) {}

  async execute(loginUserDto: LoginDto): Promise<UserAccessToken> {
    const user = await this.authRepository.login(loginUserDto);
    const accessToken = await this.signToken({ 
      uid: user.uid, 
    });

    if (!accessToken)
      throw CustomError.internalServer('Error generating accessToken');

    return {
      status: true,
      accessToken,
      user: { 
        uid: user.uid,
        username: user.username,
        role: user.role,
        is_online: user.is_online,
        picture: user.picture,
      }
    };
  }
}
```

**Equivalente NestJS (como servicio)**:

```typescript
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthRepository } from '../repositories/auth.repository';
import { LoginDto } from '../dto/login.dto';
import { CustomException } from '../../common/exceptions/custom.exception';

interface UserAccessToken {
  status: boolean;
  accessToken: string;
  user: {
    uid: string;
    username: string;
    is_online: boolean;
    role: string;
    picture?: string;
  };
}

@Injectable()
export class LoginUserUseCase {
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly jwtService: JwtService,
  ) {}

  async execute(loginDto: LoginDto): Promise<UserAccessToken> {
    const user = await this.authRepository.login(loginDto);
    
    const accessToken = this.jwtService.sign({ uid: user.uid });

    return {
      status: true,
      accessToken,
      user: { 
        uid: user.uid,
        username: user.username,
        role: user.role,
        is_online: user.is_online,
        picture: user.picture,
      }
    };
  }
}
```

---

### RegisterUser UseCase

**Archivo**: `src/domain/use-cases/auth/register.use-case.ts`

```typescript
import { JwtAdapter } from "../../../config";
import { RegisterDto } from "../../dtos/auth";
import { CustomError } from "../../errors";
import { AuthRepository } from "../../repositories";

interface UserAccessToken {
  status: boolean;
  accessToken: string;
  user: {
    uid: string;
    username: string;
    is_online: boolean;
    picture?: string;
    role: string;
    profile?: any;
  };
}

type SignToken = (payload: Object, duration?: number) => Promise<string | null>;

interface RegisterUserUseCase {
  execute(registerUserDto: RegisterDto): Promise<UserAccessToken>;
}

export class RegisterUser implements RegisterUserUseCase {
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly signToken: SignToken = JwtAdapter.generateToken
  ) {}

  async execute(registerUserDto: RegisterDto): Promise<UserAccessToken> {
    const user = await this.authRepository.register(registerUserDto);
    const accessToken = await this.signToken({
      uid: user.uid,
    });

    if (!accessToken)
      throw CustomError.internalServer("Error generating accessToken");

    return {
      status: true,
      accessToken,
      user: {
        uid: user.uid,
        role: user.role,
        username: user.username,
        is_online: user.is_online,
        picture: user.picture,
      },
    };
  }
}
```

**Equivalente NestJS (como servicio)**:

```typescript
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthRepository } from '../repositories/auth.repository';
import { RegisterDto } from '../dto/register.dto';

@Injectable()
export class RegisterUserUseCase {
  constructor(
    private readonly authRepository: AuthRepository,
    private readonly jwtService: JwtService,
  ) {}

  async execute(registerDto: RegisterDto): Promise<UserAccessToken> {
    const user = await this.authRepository.register(registerDto);
    
    const accessToken = this.jwtService.sign({ uid: user.uid });

    return {
      status: true,
      accessToken,
      user: {
        uid: user.uid,
        role: user.role,
        username: user.username,
        is_online: user.is_online,
        picture: user.picture,
      },
    };
  }
}
```

---

### Renew UseCase

**Archivo**: `src/domain/use-cases/auth/renew.use-case.ts`

```typescript
import { JwtAdapter } from "../../../config";
import { CustomError } from "../../errors";

interface User {
  uid: string;
  username: string;
  is_online: boolean;
  picture?: string;
  profile?: any;
  profileId?: string;
  role: string;
}

interface UserAccessToken {
  status: boolean;
  accessToken: string;
  user: User;
}

type SignToken = (payload: Object, duration?: number) => Promise<string | null>;

interface RenewUseCase {
  execute(user: User): Promise<UserAccessToken>;
}

export class Renew implements RenewUseCase {
  constructor(
    private readonly signToken: SignToken = JwtAdapter.generateToken,
  ) {}

  async execute(user: User): Promise<UserAccessToken> {
    
    const accessToken = await this.signToken({ uid: user.uid });
    if (!accessToken) throw CustomError.internalServer('Error generating accessToken');

    return {
      status: true,
      accessToken,
      user: { 
        uid: user.uid,
        role: user.role,
        username: user.username,
        is_online: user.is_online,
        picture: user.picture,
      }
    };
  }
}
```

**Equivalente NestJS (como servicio)**:

```typescript
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class RenewUseCase {
  constructor(private readonly jwtService: JwtService) {}

  async execute(user: User): Promise<UserAccessToken> {
    const accessToken = this.jwtService.sign({ uid: user.uid });

    return {
      status: true,
      accessToken,
      user: { 
        uid: user.uid,
        role: user.role,
        username: user.username,
        is_online: user.is_online,
        picture: user.picture,
      }
    };
  }
}
```

---

## 2. Casos de Uso de Usuario

### GetUser UseCase

**Archivo**: `src/domain/use-cases/user/get-user.ts`

```typescript
import { UserEntity } from "../../entities";
import { UserRepository } from "../../repositories";

export class GetUser {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(uid: string): Promise<UserEntity> {
        return this.userRepository.findById(uid);
    }
}
```

**Equivalente NestJS**:

```typescript
import { Injectable } from '@nestjs/common';
import { UserRepository } from '../repositories/user.repository';
import { UserEntity } from '../../domain/entities/user.entity';

@Injectable()
export class GetUserUseCase {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(uid: string): Promise<UserEntity> {
        return this.userRepository.findById(uid);
    }
}
```

---

### GetAllUsers UseCase

**Archivo**: `src/domain/use-cases/user/get-all-users.ts`

```typescript
import { UserEntity } from "../../entities";
import { UserRepository } from "../../repositories";

export class GetAllUsers {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(): Promise<UserEntity[]> {
        return this.userRepository.findAll();
    }
}
```

**Equivalente NestJS**:

```typescript
import { Injectable } from '@nestjs/common';
import { UserRepository } from '../repositories/user.repository';
import { UserEntity } from '../../domain/entities/user.entity';

@Injectable()
export class GetAllUsersUseCase {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(): Promise<UserEntity[]> {
        return this.userRepository.findAll();
    }
}
```

---

### UpdateUser UseCase

**Archivo**: `src/domain/use-cases/user/update-user.ts`

```typescript
import { UpdateUserDto } from "../../dtos/user";
import { UserEntity } from "../../entities";
import { UserRepository } from "../../repositories";

export class UpdateUser {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(updateUserDto: UpdateUserDto): Promise<UserEntity> {
        return this.userRepository.updateUser(updateUserDto);
    }
}
```

**Equivalente NestJS**:

```typescript
import { Injectable } from '@nestjs/common';
import { UserRepository } from '../repositories/user.repository';
import { UpdateUserDto } from '../dto/update-user.dto';
import { UserEntity } from '../../domain/entities/user.entity';

@Injectable()
export class UpdateUserUseCase {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(updateUserDto: UpdateUserDto): Promise<UserEntity> {
        return this.userRepository.updateUser(updateUserDto);
    }
}
```

---

### UpdateUserByAdmin UseCase

**Archivo**: `src/domain/use-cases/user/update-user-admin.ts`

```typescript
import { UpdateUserByAdminDto } from "../../dtos/user";
import { UserEntity } from "../../entities";
import { UserRepository } from "../../repositories";

export class UpdateUserByAdmin {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(updateUserByAdminDto: UpdateUserByAdminDto): Promise<UserEntity> {
        return this.userRepository.updateUserByAdmin(updateUserByAdminDto);
    }
}
```

**Equivalente NestJS**:

```typescript
import { Injectable } from '@nestjs/common';
import { UserRepository } from '../repositories/user.repository';
import { UpdateUserByAdminDto } from '../dto/update-user-admin.dto';
import { UserEntity } from '../../domain/entities/user.entity';

@Injectable()
export class UpdateUserByAdminUseCase {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(updateUserByAdminDto: UpdateUserByAdminDto): Promise<UserEntity> {
        return this.userRepository.updateUserByAdmin(updateUserByAdminDto);
    }
}
```

---

### DeleteUser UseCase

**Archivo**: `src/domain/use-cases/user/delete-user.ts`

```typescript
import { UserEntity } from "../../entities";
import { UserRepository } from "../../repositories";

export class DeleteUser {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(uid: string): Promise<UserEntity> {
        return this.userRepository.deleteUser(uid);
    }
}
```

**Equivalente NestJS**:

```typescript
import { Injectable } from '@nestjs/common';
import { UserRepository } from '../repositories/user.repository';
import { UserEntity } from '../../domain/entities/user.entity';

@Injectable()
export class DeleteUserUseCase {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(uid: string): Promise<UserEntity> {
        return this.userRepository.deleteUser(uid);
    }
}
```

---

## 3. Patrón de Respuesta de Autenticación

Todas las operaciones de autenticación devuelven la misma estructura:

```typescript
interface UserAccessToken {
  status: boolean;          // Siempre true si es exitoso
  accessToken: string;      // JWT token
  user: {
    uid: string;            // UUID del usuario
    username: string;       // Nombre de usuario
    is_online: boolean;     // Estado de conexión
    role: string;           // 'user' | 'admin'
    picture?: string;       // URL de foto de perfil (opcional)
    profile?: any;          // Datos adicionales del perfil (opcional)
  };
}
```

---

## 4. Notas para la Migración

1. **Inyección de Dependencias**: En NestJS, usa `@Injectable()` para marcar los use cases y servicios.

2. **JwtService**: NestJS provee `@nestjs/jwt` que reemplaza el `JwtAdapter` custom.

3. **Modularización**: Los use cases pueden agruparse dentro del servicio del módulo o mantenerse separados.

4. **Testing**: Los use cases con dependencias inyectadas son más fáciles de testear con mocks.
