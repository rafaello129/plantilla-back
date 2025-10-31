export class UpdateUserByAdminDto {
    private constructor(
        public targetUid: string,
        public role?: string,
        public is_active?: boolean,
        public is_disabled?: boolean,
    ) {}

    static create(object: { [key: string]: any }): [string?, UpdateUserByAdminDto?] {
        const { targetUid, role, is_active, is_disabled } = object;

        if (!targetUid) return [`Missing 'targetUid'`];

        if (role && role !== 'user' && role !== 'admin') {
            return [`Invalid 'role', must be 'user' or 'admin'`];
        }
        
        if (is_active !== undefined && typeof is_active !== 'boolean') {
            return [`'is_active' must be a boolean`];
        }

        if (is_disabled !== undefined && typeof is_disabled !== 'boolean') {
            return [`'is_disabled' must be a boolean`];
        }

        return [undefined, new UpdateUserByAdminDto(targetUid, role, is_active, is_disabled)];
    }
}   