# Guía de Migración a NestJS - Arquitectura Limpia

## Índice
1. [Resumen Ejecutivo](#resumen-ejecutivo)
2. [Estructura del Proyecto Original](#estructura-del-proyecto-original)
3. [Estructura Propuesta para NestJS](#estructura-propuesta-para-nestjs)
4. [Capas de la Arquitectura](#capas-de-la-arquitectura)
5. [Migración por Componentes](#migración-por-componentes)
6. [Configuración y Variables de Entorno](#configuración-y-variables-de-entorno)
7. [API Endpoints](#api-endpoints)
8. [Dependencias Requeridas](#dependencias-requeridas)

---

## Resumen Ejecutivo

Este backend implementa una **Arquitectura Limpia (Clean Architecture)** con Express.js y TypeORM. La migración a NestJS mantendrá los mismos principios arquitectónicos, aprovechando el sistema de módulos, inyección de dependencias nativa y decoradores de NestJS.

### Tecnologías Actuales
- **Runtime**: Node.js con TypeScript
- **Framework HTTP**: Express.js 5.x
- **ORM**: TypeORM 0.3.x
- **Base de Datos**: PostgreSQL
- **Autenticación**: JWT (jsonwebtoken)
- **WebSockets**: Socket.io
- **Encriptación**: bcryptjs

### Tecnologías Propuestas para NestJS
- **Runtime**: Node.js con TypeScript
- **Framework**: NestJS 10.x
- **ORM**: TypeORM 0.3.x (o @nestjs/typeorm)
- **Base de Datos**: PostgreSQL
- **Autenticación**: @nestjs/jwt + @nestjs/passport
- **WebSockets**: @nestjs/websockets + @nestjs/platform-socket.io
- **Encriptación**: bcryptjs

---

## Estructura del Proyecto Original

```
src/
├── app.ts                      # Punto de entrada principal
├── config/                     # Configuración global
│   ├── bcrypt.ts              # Adaptador de encriptación
│   ├── envs.ts                # Variables de entorno
│   ├── jwt.ts                 # Adaptador JWT
│   ├── validators.ts          # Validadores regex
│   └── index.ts               # Exportaciones
├── data/                       # Capa de datos (infraestructura DB)
│   └── postgres/
│       ├── entities/          # Entidades TypeORM (modelos DB)
│       │   ├── user.entity.ts
│       │   └── index.ts
│       ├── postgres-database.ts # Conexión a la base de datos
│       └── index.ts
├── domain/                     # Capa de dominio (núcleo del negocio)
│   ├── datasources/           # Contratos abstractos de datasources
│   │   ├── auth.datasource.ts
│   │   ├── user.datasource.ts
│   │   └── index.ts
│   ├── dtos/                  # Data Transfer Objects
│   │   ├── auth/
│   │   │   ├── login.dto.ts
│   │   │   ├── register.dto.ts
│   │   │   └── index.ts
│   │   ├── user/
│   │   │   ├── update-user.dto.ts
│   │   │   ├── update-user-admin.dto.ts
│   │   │   └── index.ts
│   │   └── index.ts
│   ├── entities/              # Entidades de dominio
│   │   ├── user.entity.ts
│   │   └── index.ts
│   ├── errors/                # Errores personalizados
│   │   ├── custom.error.ts
│   │   └── index.ts
│   ├── repositories/          # Contratos abstractos de repositorios
│   │   ├── auth.repository.ts
│   │   ├── user.repository.ts
│   │   └── index.ts
│   └── use-cases/             # Casos de uso
│       ├── auth/
│       │   ├── login.use-case.ts
│       │   ├── register.use-case.ts
│       │   ├── renew.use-case.ts
│       │   └── index.ts
│       └── user/
│           ├── get-user.ts
│           ├── get-all-users.ts
│           ├── update-user.ts
│           ├── update-user-admin.ts
│           ├── delete-user.ts
│           └── index.ts
├── infrastructure/             # Capa de infraestructura
│   ├── datasources/           # Implementaciones de datasources
│   │   ├── auth.datasource.impl.ts
│   │   ├── user.datasource.impl.ts
│   │   └── index.ts
│   ├── mappers/               # Mapeadores de entidades
│   │   ├── user.mapper.ts
│   │   └── index.ts
│   ├── repositories/          # Implementaciones de repositorios
│   │   ├── auth.repository.impl.ts
│   │   ├── user.repository.impl.ts
│   │   └── index.ts
│   └── sockets/               # Eventos de sockets
│       └── users.envent.ts
├── presentation/               # Capa de presentación
│   ├── auth/                  # Módulo de autenticación
│   │   ├── controller.ts
│   │   └── routes.ts
│   ├── middlewares/           # Middlewares
│   │   ├── auth.middleware.ts
│   │   ├── role.middleware.ts
│   │   └── index.ts
│   ├── user/                  # Módulo de usuarios
│   │   ├── controller.ts
│   │   └── routes.ts
│   ├── public/                # Archivos estáticos
│   ├── routes.ts              # Rutas principales
│   ├── server.ts              # Configuración del servidor
│   └── sockets.ts             # Manejo de WebSockets
└── templates/                  # Plantillas (handlebars)
    └── welcome.hbs
```

---

## Estructura Propuesta para NestJS

```
src/
├── main.ts                           # Punto de entrada
├── app.module.ts                     # Módulo raíz
├── common/                           # Elementos compartidos
│   ├── config/
│   │   ├── configuration.ts          # Configuración TypedConfig
│   │   └── validation.schema.ts      # Esquema Joi para validación
│   ├── decorators/
│   │   └── get-user.decorator.ts     # Decorador para obtener usuario
│   ├── exceptions/
│   │   ├── custom.exception.ts       # Excepción personalizada
│   │   └── http-exception.filter.ts  # Filtro global de excepciones
│   ├── guards/
│   │   ├── jwt-auth.guard.ts         # Guard de autenticación JWT
│   │   └── roles.guard.ts            # Guard de roles
│   └── interceptors/
│       └── transform.interceptor.ts  # Interceptor de transformación
├── database/                         # Configuración de base de datos
│   ├── database.module.ts
│   └── entities/                     # Entidades TypeORM
│       ├── user.entity.ts
│       └── index.ts
├── domain/                           # Capa de dominio
│   ├── entities/                     # Entidades de dominio
│   │   └── user.entity.ts
│   ├── repositories/                 # Contratos abstractos
│   │   ├── auth.repository.ts
│   │   └── user.repository.ts
│   └── use-cases/                    # Casos de uso
│       ├── auth/
│       │   ├── login.use-case.ts
│       │   ├── register.use-case.ts
│       │   └── renew.use-case.ts
│       └── user/
│           ├── get-user.use-case.ts
│           ├── get-all-users.use-case.ts
│           ├── update-user.use-case.ts
│           ├── update-user-admin.use-case.ts
│           └── delete-user.use-case.ts
├── modules/
│   ├── auth/                         # Módulo de autenticación
│   │   ├── auth.module.ts
│   │   ├── auth.controller.ts
│   │   ├── auth.service.ts
│   │   ├── dto/
│   │   │   ├── login.dto.ts
│   │   │   └── register.dto.ts
│   │   ├── strategies/
│   │   │   └── jwt.strategy.ts
│   │   └── interfaces/
│   │       └── jwt-payload.interface.ts
│   └── user/                         # Módulo de usuarios
│       ├── user.module.ts
│       ├── user.controller.ts
│       ├── user.service.ts
│       ├── dto/
│       │   ├── update-user.dto.ts
│       │   └── update-user-admin.dto.ts
│       └── repositories/
│           ├── user.repository.ts    # Contrato
│           └── user.repository.impl.ts # Implementación
└── gateways/                         # WebSocket Gateways
    └── user.gateway.ts
```

