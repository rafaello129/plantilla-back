import { UserEntity } from "../../entities";
import { UserRepository } from "../../repositories";

export class DeleteUser {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(uid: string): Promise<UserEntity> {
        return this.userRepository.deleteUser(uid);
    }
}