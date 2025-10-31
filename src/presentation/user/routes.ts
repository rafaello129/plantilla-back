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