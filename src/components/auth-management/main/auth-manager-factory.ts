import { AuthManager } from './auth-manager';
import { InMemoryUserRepository } from './infra/in-memory-user-repository';

const AuthManagerFactory = {
    Instance(): AuthManager {
        return new AuthManager(new InMemoryUserRepository());
    },
};

export { AuthManagerFactory };
