import { Not, QueryRunner } from "typeorm";
import { BcryptAdapter } from "../../config";
import { PostgresDatabase } from "../../data/postgres";
import { User } from "../../data/postgres/entities/user.entity";
import { AuthDatasource } from "../../domain/datasources";
import { LoginDto, RegisterDto } from "../../domain/dtos/auth";
import { UserEntity } from "../../domain/entities";
import { CustomError } from "../../domain/errors";
import { UserMapper } from "../mappers";

type HashFunction = (password: string) => string;
type CompareFunction = (password: string, hashed: string) => boolean;

export class AuthDatasourceImpl implements AuthDatasource {
    
    constructor(
        private readonly hashPassword: HashFunction = BcryptAdapter.hash,
        private readonly comparePassword: CompareFunction = BcryptAdapter.compare,
    ) {}
  

    async login(loginDto: LoginDto): Promise<UserEntity> {
        const { username, password } = loginDto;
        const queryRunner = PostgresDatabase.dataSource.createQueryRunner();

        await queryRunner.connect();

        try {
            const user = await this.findUser(queryRunner, username);

            if (!user) {
                throw CustomError.badRequest(`Credenciales incorrectas.`);
            }

            this.validatePassword(password, user.password!);

            return UserMapper.userEntityFromObject({ ...user });
        } catch (error) {
         
            if (error instanceof CustomError) throw error;
            throw CustomError.internalServer();
        } finally {
            await queryRunner.release(); // Siempre se libera
        }
    }

    private async findUser(
        queryRunner: QueryRunner, 
        username: string, 
    ) {
        return await queryRunner.manager.findOne(User, {
            where: [
                { username: username.toLowerCase(), is_active: true },
                { email: username.toLowerCase(), is_active: true },
            ],
            select: {
                uid: true,
                username: true,
                email: true,
                phone: true,
                password: true,
                is_active: true,
                is_online: true,
                is_disabled: true,
                is_google: true,
                created_at: true,
                updated_at: true,
                picture: true,
                role: true,
            }
        });
    }


    private validatePassword(password: string, hashedPassword: string) {
        const isMatching = this.comparePassword(password, hashedPassword);
        if (!isMatching) {
            throw CustomError.badRequest('Credenciales incorrectas.');
        }
    }

    async register(registerUserDto: RegisterDto): Promise<UserEntity> {
        const { name, username, password, role } = registerUserDto;
        const queryRunner = PostgresDatabase.dataSource.createQueryRunner();

        await queryRunner.connect();

        try {
            await queryRunner.startTransaction();

            const userdb = await queryRunner.manager.findOne(User, {
                where: [
                    { username: username.toLowerCase() },
                    { email: username.toLowerCase() }
                ],
            });

            if (userdb) {
                throw CustomError.badRequest(
                    `Ya existe un usuario con el username '${username.toLowerCase()}'`
                );
            }

            const user = queryRunner.manager.create(User, {
                name,
                username,
                 role,
                email: username,
                password: this.hashPassword(password),
            });

            await queryRunner.manager.save(user);

            await queryRunner.commitTransaction(); // Commit solo si todo salió bien

            return UserMapper.userEntityFromObject({ ...user });
        } catch (error) {
            console.log(error);
            await queryRunner.rollbackTransaction(); // Rollback en caso de error
            if (error instanceof CustomError) throw error;
            throw CustomError.internalServer();
        } finally {
            await queryRunner.release(); // Siempre liberar
        }
    }

    
}
