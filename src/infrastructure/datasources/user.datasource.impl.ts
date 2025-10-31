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