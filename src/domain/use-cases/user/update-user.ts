import { UpdateUserDto } from "../../dtos/user";
import { UserEntity } from "../../entities";
import { UserRepository } from "../../repositories";

export class UpdateUser {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(updateUserDto: UpdateUserDto): Promise<UserEntity> {
        return this.userRepository.updateUser(updateUserDto);
    }
}