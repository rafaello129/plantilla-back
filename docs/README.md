# Guía Completa de Migración - Express Clean Architecture a NestJS

## 📋 Documentación Disponible

Esta carpeta contiene toda la documentación necesaria para migrar el backend de Express.js con Arquitectura Limpia a NestJS.

### Archivos de Documentación

| Archivo | Descripción |
|---------|-------------|
| [NESTJS_MIGRATION_GUIDE.md](./NESTJS_MIGRATION_GUIDE.md) | Guía principal con estructura general |
| [01-DOMAIN-LAYER.md](./01-DOMAIN-LAYER.md) | Entidades, DTOs, Datasources, Repositorios y Errores |
| [02-USE-CASES.md](./02-USE-CASES.md) | Casos de uso de Auth y User |
| [03-DATA-INFRASTRUCTURE-LAYER.md](./03-DATA-INFRASTRUCTURE-LAYER.md) | Entidades TypeORM, conexión DB, mappers e implementaciones |
| [04-PRESENTATION-LAYER.md](./04-PRESENTATION-LAYER.md) | Controladores, rutas, middlewares y guards |
| [05-WEBSOCKETS-CONFIG.md](./05-WEBSOCKETS-CONFIG.md) | WebSockets con Socket.io y configuración |
| [06-API-ENDPOINTS-DEPENDENCIES.md](./06-API-ENDPOINTS-DEPENDENCIES.md) | Resumen de API, dependencias y comandos |

---

## 🎯 Resumen Ejecutivo para el Agente

### Tecnología Origen
- **Framework**: Express.js 5.x
- **ORM**: TypeORM 0.3.x
- **Base de Datos**: PostgreSQL
- **Autenticación**: JWT manual con jsonwebtoken
- **WebSockets**: Socket.io
- **Lenguaje**: TypeScript

### Tecnología Destino
- **Framework**: NestJS 10.x
- **ORM**: @nestjs/typeorm + TypeORM 0.3.x
- **Base de Datos**: PostgreSQL
- **Autenticación**: @nestjs/jwt + @nestjs/passport
- **WebSockets**: @nestjs/websockets + @nestjs/platform-socket.io
- **Lenguaje**: TypeScript

---

## 📁 Estructura del Proyecto Original

```
src/
├── app.ts                      # Entry point
├── config/                     # Configuración (envs, jwt, bcrypt)
├── data/postgres/              # Conexión DB + Entidades TypeORM
├── domain/                     # Capa de dominio
│   ├── datasources/           # Contratos abstractos
│   ├── dtos/                  # DTOs con validación
│   ├── entities/              # Entidades de dominio
│   ├── errors/                # CustomError
│   ├── repositories/          # Contratos de repositorios
│   └── use-cases/             # Casos de uso
├── infrastructure/             # Implementaciones
│   ├── datasources/           # Impl de datasources
│   ├── mappers/               # Mappers
│   ├── repositories/          # Impl de repositorios
│   └── sockets/               # Eventos de socket
└── presentation/               # Capa de presentación
    ├── auth/                  # Auth controller + routes
    ├── middlewares/           # Auth + Role middlewares
    ├── user/                  # User controller + routes
    ├── routes.ts              # Rutas principales
    ├── server.ts              # Servidor Express
    └── sockets.ts             # Socket handler
```

---

## 📁 Estructura Sugerida para NestJS

```
src/
├── main.ts
├── app.module.ts
├── common/
│   ├── config/
│   ├── decorators/
│   ├── exceptions/
│   ├── guards/
│   └── interceptors/
├── database/
│   ├── database.module.ts
│   └── entities/
├── domain/
│   ├── entities/
│   ├── repositories/
│   └── use-cases/
├── modules/
│   ├── auth/
│   │   ├── auth.module.ts
│   │   ├── auth.controller.ts
│   │   ├── auth.service.ts
│   │   ├── dto/
│   │   └── strategies/
│   └── user/
│       ├── user.module.ts
│       ├── user.controller.ts
│       ├── user.service.ts
│       └── dto/
└── gateways/
    └── user.gateway.ts
```

---

## 🔑 Funcionalidades a Migrar

### Autenticación
- [x] Login con username/email y password
- [x] Registro de usuarios con rol (user/admin)
- [x] Renovación de token JWT
- [x] Validación de token en requests

### Gestión de Usuarios
- [x] Obtener perfil propio
- [x] Actualizar perfil propio (name, email, phone, picture)
- [x] Desactivar cuenta propia (soft delete)
- [x] Listar todos los usuarios (admin)
- [x] Actualizar usuario por admin (role, is_active, is_disabled)

### WebSockets
- [x] Autenticación por token en conexión
- [x] Actualizar estado online/offline
- [x] Manejo de desconexión

---

## ⚙️ Variables de Entorno

```env
# Servidor
HOST=0.0.0.0
PORT=3500

# PostgreSQL
HOST_DB=localhost
PORT_DB=5432
USERNAME_DB=username
PASSWORD_DB=password
DATABASE_DB=database

# JWT
JWT_SEED=your_secret_seed
```

---

## 🚀 Pasos de Migración Sugeridos

1. **Inicializar proyecto NestJS**
   ```bash
   nest new nest-backend
   ```

2. **Instalar dependencias**
   ```bash
   npm install @nestjs/typeorm typeorm pg
   npm install @nestjs/jwt @nestjs/passport passport passport-jwt
   npm install @nestjs/config joi
   npm install @nestjs/websockets @nestjs/platform-socket.io socket.io
   npm install bcryptjs class-validator class-transformer
   npm install -D @types/bcryptjs @types/passport-jwt
   ```

3. **Configurar módulos base**
   - ConfigModule con validación
   - DatabaseModule con TypeORM

4. **Implementar AuthModule**
   - DTOs con class-validator
   - JwtStrategy
   - AuthService
   - AuthController

5. **Implementar UserModule**
   - DTOs
   - UserService
   - UserController con guards

6. **Implementar WebSocket Gateway**
   - UserGateway
   - Autenticación de socket

7. **Configurar elementos comunes**
   - CustomException
   - Guards (JwtAuthGuard, RolesGuard)
   - Decoradores (@GetUser, @Roles)

---

## 📝 Notas Importantes

1. **Validación de DTOs**: Cambiar de factory methods a decoradores de `class-validator`

2. **Inyección de Dependencias**: NestJS la maneja automáticamente con `@Injectable()`

3. **Middleware → Guards**: Los middlewares de autenticación se convierten en Guards

4. **Rutas → Controladores**: Los archivos routes.ts se convierten en controladores con decoradores

5. **Manejo de Errores**: Usar HttpException y filtros de excepciones de NestJS

6. **WebSockets**: Usar decoradores de NestJS en lugar de configurar Socket.io manualmente

---

## 📞 Contacto y Soporte

Para cualquier duda sobre la migración, consultar la documentación detallada en cada archivo de esta carpeta.
