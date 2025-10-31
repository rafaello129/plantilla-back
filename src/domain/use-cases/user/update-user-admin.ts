import { UpdateUserByAdminDto } from "../../dtos/user";
import { UserEntity } from "../../entities";
import { UserRepository } from "../../repositories";

export class UpdateUserByAdmin {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(updateUserByAdminDto: UpdateUserByAdminDto): Promise<UserEntity> {
        return this.userRepository.updateUserByAdmin(updateUserByAdminDto);
    }
}