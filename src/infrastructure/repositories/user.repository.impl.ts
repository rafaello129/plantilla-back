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