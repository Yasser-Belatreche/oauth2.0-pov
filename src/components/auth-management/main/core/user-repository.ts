import { type User } from './user';

export interface UserRepository {
    getByAccessToken(accessToken: string): Promise<User | undefined>;

    getByRefreshToken(refreshToken: string): Promise<User | undefined>;

    getById(id: string): Promise<User | undefined>;

    save(user: User): Promise<void>;
}
