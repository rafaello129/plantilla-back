import { UpdateUserByAdminDto, UpdateUserDto } from "../dtos/user";
import { UserEntity } from "../entities";

export abstract class UserDatasource {
    abstract findById(uid: string): Promise<UserEntity>;
    abstract findAll(): Promise<UserEntity[]>;
    abstract updateUser(updateUserDto: UpdateUserDto): Promise<UserEntity>;
    abstract updateUserByAdmin(updateUserByAdminDto: UpdateUserByAdminDto): Promise<UserEntity>;
    abstract deleteUser(uid: string): Promise<UserEntity>;
}