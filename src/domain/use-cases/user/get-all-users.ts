import { UserEntity } from "../../entities";
import { UserRepository } from "../../repositories";

export class GetAllUsers {
    constructor(private readonly userRepository: UserRepository) {}

    async execute(): Promise<UserEntity[]> {
        return this.userRepository.findAll();
    }
}