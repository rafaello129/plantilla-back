import { UserEntity } from "../../entities";
import { UserRepository } from "../../repositories";

export class GetUser {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(uid: string): Promise<UserEntity> {
        return this.userRepository.findById(uid);
    }
}