# API Endpoints y Dependencias

Este documento resume los endpoints de la API y las dependencias necesarias para la migración a NestJS.

---

## 1. Resumen de API Endpoints

### Autenticación (`/api/auth`)

| Método | Endpoint | Descripción | Body | Autenticación |
|--------|----------|-------------|------|---------------|
| POST | `/login/:role` | Iniciar sesión | `{ username, password }` | No |
| POST | `/register/:role` | Registrar usuario | `{ name, username, password }` | No |
| POST | `/renew` | Renovar token JWT | - | Sí (Bearer Token) |

**Parámetros de ruta:**
- `role`: 'user' o 'admin'

**Respuesta exitosa de login/register/renew:**
```json
{
  "status": true,
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "uid": "uuid-del-usuario",
    "username": "john_doe",
    "role": "user",
    "is_online": true,
    "picture": "https://url-to-picture.com/pic.jpg"
  }
}
```

---

### Usuarios (`/api/users`)

| Método | Endpoint | Descripción | Body | Autenticación | Rol |
|--------|----------|-------------|------|---------------|-----|
| GET | `/profile` | Obtener perfil propio | - | Sí | Cualquiera |
| PUT | `/profile` | Actualizar perfil propio | `{ name?, email?, phone?, picture? }` | Sí | Cualquiera |
| DELETE | `/profile` | Desactivar cuenta propia (soft delete) | - | Sí | Cualquiera |
| GET | `/` | Listar todos los usuarios | - | Sí | Admin |
| PUT | `/:uid` | Actualizar usuario por admin | `{ role?, is_active?, is_disabled? }` | Sí | Admin |

**Respuesta de perfil de usuario:**
```json
{
  "uid": "uuid-del-usuario",
  "name": "John Doe",
  "username": "john_doe",
  "email": "john@example.com",
  "phone": "+1234567890",
  "picture": "https://url-to-picture.com/pic.jpg",
  "is_active": true,
  "is_online": true,
  "is_disabled": false,
  "is_google": false,
  "role": "user",
  "created_at": "2024-01-01T00:00:00.000Z",
  "updated_at": "2024-01-01T00:00:00.000Z"
}
```

---

## 2. Códigos de Error HTTP

| Código | Descripción | Uso |
|--------|-------------|-----|
| 400 | Bad Request | Validación fallida, datos inválidos |
| 401 | Unauthorized | Token inválido o faltante, credenciales incorrectas |
| 403 | Forbidden | Acceso denegado (falta rol admin) |
| 404 | Not Found | Usuario no encontrado |
| 409 | Conflict | Email o teléfono ya existe |
| 500 | Internal Server Error | Error interno del servidor |

---

## 3. Esquema de Base de Datos

### Tabla: users

| Columna | Tipo | Constraints | Default |
|---------|------|-------------|---------|
| uid | UUID | PRIMARY KEY | auto-generated |
| name | VARCHAR | NOT NULL | - |
| role | VARCHAR | NOT NULL | 'user' |
| username | VARCHAR | UNIQUE, NOT NULL | - |
| email | VARCHAR | UNIQUE, NOT NULL | - |
| phone | VARCHAR | UNIQUE, NULLABLE | NULL |
| password | VARCHAR | NOT NULL | - |
| picture | VARCHAR | NULLABLE | NULL |
| is_active | BOOLEAN | NOT NULL | true |
| is_online | BOOLEAN | NOT NULL | false |
| is_disabled | BOOLEAN | NOT NULL | false |
| is_google | BOOLEAN | NOT NULL | false |
| created_at | TIMESTAMP | NOT NULL | CURRENT_TIMESTAMP |
| updated_at | TIMESTAMP | NOT NULL | CURRENT_TIMESTAMP (on update) |

---

## 4. Dependencias del Proyecto Original

### package.json

```json
{
  "name": "server",
  "version": "1.0.0",
  "type": "commonjs",
  "main": "index.js",
  "scripts": {
    "dev": "tsnd --respawn --clear src/app.ts",
    "build": "rimraf ./dist && tsc",
    "start": "npm run build && node dist/app.js"
  },
  "dependencies": {
    "axios": "^1.12.2",
    "bcryptjs": "^3.0.2",
    "cors": "^2.8.5",
    "dotenv": "^17.2.3",
    "env-var": "^7.5.0",
    "express": "^5.1.0",
    "jsonwebtoken": "^9.0.2",
    "morgan": "^1.10.1",
    "mysql2": "^3.15.2",
    "pg": "^8.16.3",
    "socket.io": "^4.8.1",
    "ts-node-dev": "^2.0.0",
    "typeorm": "^0.3.27"
  },
  "devDependencies": {
    "@types/cors": "^2.8.19",
    "@types/express": "^5.0.3",
    "@types/jsonwebtoken": "^9.0.10",
    "@types/morgan": "^1.9.10",
    "typescript": "^5.9.3"
  }
}
```

---

## 5. Dependencias Sugeridas para NestJS

### package.json para NestJS

```json
{
  "name": "nest-server",
  "version": "1.0.0",
  "scripts": {
    "build": "nest build",
    "start": "nest start",
    "start:dev": "nest start --watch",
    "start:debug": "nest start --debug --watch",
    "start:prod": "node dist/main",
    "lint": "eslint \"{src,apps,libs,test}/**/*.ts\" --fix",
    "test": "jest",
    "test:watch": "jest --watch",
    "test:cov": "jest --coverage",
    "test:e2e": "jest --config ./test/jest-e2e.json"
  },
  "dependencies": {
    "@nestjs/common": "^10.0.0",
    "@nestjs/core": "^10.0.0",
    "@nestjs/platform-express": "^10.0.0",
    "@nestjs/typeorm": "^10.0.0",
    "@nestjs/jwt": "^10.0.0",
    "@nestjs/passport": "^10.0.0",
    "@nestjs/config": "^3.0.0",
    "@nestjs/websockets": "^10.0.0",
    "@nestjs/platform-socket.io": "^10.0.0",
    "passport": "^0.6.0",
    "passport-jwt": "^4.0.0",
    "bcryptjs": "^2.4.3",
    "class-validator": "^0.14.0",
    "class-transformer": "^0.5.1",
    "typeorm": "^0.3.27",
    "pg": "^8.16.3",
    "socket.io": "^4.8.1",
    "reflect-metadata": "^0.1.13",
    "rxjs": "^7.8.1",
    "joi": "^17.9.0"
  },
  "devDependencies": {
    "@nestjs/cli": "^10.0.0",
    "@nestjs/schematics": "^10.0.0",
    "@nestjs/testing": "^10.0.0",
    "@types/bcryptjs": "^2.4.2",
    "@types/passport-jwt": "^3.0.8",
    "@types/node": "^20.0.0",
    "@types/jest": "^29.5.0",
    "@typescript-eslint/eslint-plugin": "^6.0.0",
    "@typescript-eslint/parser": "^6.0.0",
    "eslint": "^8.42.0",
    "eslint-config-prettier": "^9.0.0",
    "eslint-plugin-prettier": "^5.0.0",
    "jest": "^29.5.0",
    "prettier": "^3.0.0",
    "source-map-support": "^0.5.21",
    "ts-jest": "^29.1.0",
    "ts-loader": "^9.4.3",
    "ts-node": "^10.9.1",
    "tsconfig-paths": "^4.2.0",
    "typescript": "^5.1.3"
  }
}
```

---

## 6. Mapeo de Dependencias

| Express Original | NestJS Equivalente |
|------------------|-------------------|
| express | @nestjs/platform-express |
| cors | Habilitado con `app.enableCors()` |
| morgan | Interceptor personalizado o logger integrado |
| jsonwebtoken | @nestjs/jwt |
| dotenv + env-var | @nestjs/config + joi |
| typeorm | @nestjs/typeorm + typeorm |
| socket.io | @nestjs/websockets + @nestjs/platform-socket.io |
| bcryptjs | bcryptjs (sin cambios) |

---

## 7. Comandos para Iniciar Proyecto NestJS

```bash
# Instalar NestJS CLI globalmente
npm i -g @nestjs/cli

# Crear nuevo proyecto
nest new nest-backend

# Instalar dependencias adicionales
npm install @nestjs/typeorm typeorm pg
npm install @nestjs/jwt @nestjs/passport passport passport-jwt
npm install @nestjs/config joi
npm install @nestjs/websockets @nestjs/platform-socket.io socket.io
npm install bcryptjs class-validator class-transformer

# Tipos de desarrollo
npm install -D @types/bcryptjs @types/passport-jwt

# Generar módulos
nest g module database
nest g module auth
nest g module user
nest g gateway user gateways
```

---

## 8. Estructura de Archivos a Crear

```bash
# Comandos nest g para generar estructura
nest g module common
nest g module database
nest g module modules/auth
nest g module modules/user
nest g controller modules/auth --flat
nest g controller modules/user --flat
nest g service modules/auth --flat
nest g service modules/user --flat
nest g gateway gateways/user
```

---

## 9. Notas Finales para el Agente de Migración

### Prioridades de Implementación

1. **Configuración Base**
   - Crear estructura de carpetas
   - Configurar ConfigModule con validación Joi
   - Configurar DatabaseModule con TypeORM

2. **Módulo de Autenticación**
   - Implementar AuthModule con JWT
   - Crear JwtStrategy
   - Implementar DTOs con class-validator
   - Crear AuthService con casos de uso

3. **Módulo de Usuario**
   - Implementar UserModule
   - Crear UserService
   - Implementar DTOs
   - Configurar guards para roles

4. **WebSocket Gateway**
   - Implementar UserGateway
   - Manejar conexión/desconexión
   - Validar tokens en handshake

5. **Elementos Comunes**
   - Crear CustomException
   - Implementar filtro de excepciones
   - Crear decorador @GetUser
   - Implementar guards (JwtAuthGuard, RolesGuard)

### Patrones a Mantener

- **Clean Architecture**: Separación de capas (domain, infrastructure, presentation)
- **Repository Pattern**: Abstracción de acceso a datos
- **Use Cases**: Encapsulación de lógica de negocio
- **DTOs**: Validación y transformación de datos
- **Dependency Injection**: Aprovechado nativamente por NestJS

### Diferencias Principales

| Aspecto | Express Original | NestJS |
|---------|-----------------|--------|
| DI | Manual | Nativo con decoradores |
| Validación | Factory method en DTOs | class-validator |
| Middleware Auth | Función express | PassportStrategy + Guards |
| Rutas | Router.use() | Decoradores @Controller, @Get, etc. |
| Módulos | Archivos index.ts | @Module decorador |
| WebSockets | Socket.io directo | @WebSocketGateway |
