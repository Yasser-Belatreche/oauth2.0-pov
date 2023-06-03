import { User, type UserInfo } from './core/user';

import { AuthenticationException } from './core/exception/authentication-exception';

import { type UserRepository } from './core/user-repository';
import { ClientInfo } from './core/client';

class AuthManager {
    constructor(private readonly userRepository: UserRepository) {}

    async generateTokensFor(dto: UserInfo): Promise<{ accessToken: string; refreshToken: string }> {
        let user = await this.userRepository.getById(dto.id);

        if (!user) user = User.Create(dto);

        const tokens = await user.generateNewTokens();

        await this.userRepository.save(user);

        return tokens;
    }

    async generateTokensWithIdentity(
        dto: UserInfo,
        identity: Record<string, string>,
    ): Promise<{ accessToken: string; refreshToken: string; idToken: string }> {
        let user = await this.userRepository.getById(dto.id);

        if (!user) user = User.Create(dto);

        const tokens = await user.generateNewTokensWithIdentity(identity);

        await this.userRepository.save(user);

        return tokens;
    }

    async generateClient(dto: UserInfo, client: ClientInfo) {
        let user = await this.userRepository.getById(dto.id);

        if (!user) user = User.Create(dto);

        const created = user.generateNewClient(client);

        await this.userRepository.save(user);

        return created;
    }

    async getClientsOf(userId: string) {
        const user = await this.userRepository.getById(userId);

        if (!user) return [];

        return user.getClients();
    }

    async generateClientRedirectUrl(
        userInfo: UserInfo,
        client: {
            clientId: string;
            redirectUrl: string;
            state: string;
            scope: string[];
        },
    ): Promise<{ redirectUrl: string }> {
        const user = await this.userRepository.getById(userInfo.id);

        if (!user) throw new AuthenticationException('invalid token');

        const redirectUrl = user.generateRedirectUrlFor(client);

        await this.userRepository.save(user);

        return { redirectUrl };
    }

    async generateClientTokens(
        userInfo: UserInfo,
        client: {
            clientId: string;
            clientSecret: string;
            redirectUrl: string;
            code: string;
        },
    ) {
        const user = await this.userRepository.getById(userInfo.id);

        if (!user) throw new AuthenticationException('invalid token');

        const tokens = await user.generateClientTokens(client);

        await this.userRepository.save(user);

        return tokens;
    }

    async decodeToken(
        accessToken: string,
    ): Promise<{ user: UserInfo; client?: { id: string; scope: string[] } }> {
        const user = await this.userRepository.getByAccessToken(accessToken);

        if (!user) throw new AuthenticationException('invalid token');

        const isTokenValid = await user.haveValidToken(accessToken);

        if (!isTokenValid) throw new AuthenticationException('invalid token');

        return { user: user.getUserInfo(), client: user.getClientWhoHaveAccessToken(accessToken) };
    }

    async refreshToken(
        refreshToken: string,
    ): Promise<{ accessToken: string; refreshToken: string }> {
        const user = await this.userRepository.getByRefreshToken(refreshToken);

        if (!user) throw new AuthenticationException('invalid refresh token');

        const tokens = await user.refreshToken(refreshToken);

        await this.userRepository.save(user);

        return tokens.values;
    }

    async revokeToken(accessToken: string): Promise<void> {
        const user = await this.userRepository.getByAccessToken(accessToken);

        if (!user) throw new AuthenticationException('invalid refresh token');

        await user.revokeToken(accessToken);

        await this.userRepository.save(user);
    }
}

export { AuthManager };
