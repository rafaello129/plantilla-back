import { Validators } from "../../../config";

export class UpdateUserDto {
    private constructor(
        public uid: string,
        public name?: string,
        public email?: string,
        public phone?: string,
        public picture?: string,
    ) {}

    static create(object: { [key: string]: any }): [string?, UpdateUserDto?] {
        const { uid, name, email, phone, picture } = object;

        if (!uid) return [`Missing 'uid'`];

        if (email && !Validators.email.test(email)) {
            return [`Invalid 'email'`];
        }

        return [undefined, new UpdateUserDto(uid, name, email, phone, picture)];
    }
}