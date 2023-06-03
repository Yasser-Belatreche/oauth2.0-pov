import { User } from '../core/user';
import { UserRepository } from '../core/user-repository';

class InMemoryUserRepository implements UserRepository {
    private readonly map = new Map<string, User['state']>();

    async getById(id: string): Promise<User | undefined> {
        const state = this.map.get(id);

        if (!state) return undefined;

        return User.FromState(state);
    }

    async getByAccessToken(accessToken: string): Promise<User | undefined> {
        for (const user of this.map.values()) {
            if (user.tokens.find(tokens => tokens.accessToken === accessToken)) {
                return User.FromState(user);
            }

            if (user.clients.find(client => client.tokens?.accessToken === accessToken)) {
                return User.FromState(user);
            }
        }

        return undefined;
    }

    async getByRefreshToken(token: string): Promise<User | undefined> {
        for (const user of this.map.values()) {
            if (user.tokens.find(tokens => tokens.refreshToken === token)) {
                return User.FromState(user);
            }

            if (user.clients.find(client => client.tokens?.refreshToken === token)) {
                return User.FromState(user);
            }
        }

        return undefined;
    }

    async save(user: User): Promise<void> {
        this.map.set(user.state.id, user.state);
    }
}

export { InMemoryUserRepository };
