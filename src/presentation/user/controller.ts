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