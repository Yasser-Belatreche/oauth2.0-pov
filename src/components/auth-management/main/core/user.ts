import { TokensSet } from './tokens-set';
import { Client, ClientInfo } from './client';

import { AuthenticationException } from './exception/authentication-exception';

export type UserInfo = ReturnType<User['getUserInfo']>;

class User {
    static Create(dto: UserInfo) {
        return new User(dto.id, dto.role, [], []);
    }

    static FromState(state: User['state']) {
        return new User(
            state.id,
            state.role,
            state.tokens.map(token => TokensSet.FromState(token)),
            state.clients.map(clients => Client.FromState(clients)),
        );
    }

    private constructor(
        private readonly id: string,
        private readonly role: string,
        private tokens: TokensSet[],
        private readonly clients: Client[],
    ) {}

    get state() {
        return {
            id: this.id,
            role: this.role,
            tokens: this.tokens.map(token => token.state),
            clients: this.clients.map(client => client.state),
        };
    }

    getUserInfo() {
        return { id: this.id, role: this.role };
    }

    getClients() {
        return this.clients.map(client => client.getBasicInfo());
    }

    async generateNewTokens() {
        const tokens = await TokensSet.GenerateFor(this.id);

        this.tokens.push(tokens);

        return tokens.values;
    }

    async generateNewTokensWithIdentity(identity: Record<string, string>) {
        const tokens = await TokensSet.GenerateWithIdentity(this.id, identity);

        this.tokens.push(tokens);

        return {
            ...tokens.values,
            idToken: tokens.state.idToken!,
        };
    }

    generateNewClient(info: ClientInfo) {
        const client = Client.Generate(info);

        this.clients.push(client);

        return client.getBasicInfo();
    }

    generateRedirectUrlFor(info: {
        clientId: string;
        redirectUrl: string;
        state: string;
        scope: string[];
    }): string {
        const targetClient = this.getClientById(info.clientId);

        if (!targetClient) throw new AuthenticationException('client not found');

        return targetClient.generateRedirectUrl(info.redirectUrl, info.state, info.scope);
    }

    async generateClientTokens(info: {
        clientId: string;
        clientSecret: string;
        redirectUrl: string;
        code: string;
    }) {
        const targetClient = this.getClientById(info.clientId);

        if (!targetClient) throw new AuthenticationException('client not found');

        const tokens = await targetClient.generateTokens(
            info.code,
            info.redirectUrl,
            info.clientSecret,
        );

        return tokens.values;
    }

    async haveValidToken(accessToken: string): Promise<boolean> {
        for (const tokenSet of this.tokens) {
            if (tokenSet.accessTokenEquals(accessToken)) {
                return await tokenSet.isAccessTokenStillValid();
            }
        }

        for (const client of this.clients) {
            if (client.haveAccessToken(accessToken)) {
                return await client.isAccessTokenStillValid();
            }
        }

        return false;
    }

    getClientWhoHaveAccessToken(token: string): { id: string; scope: string[] } | undefined {
        for (const client of this.clients) {
            if (client.haveAccessToken(token)) {
                return {
                    id: client.state.id,
                    scope: client.state.scope,
                };
            }
        }

        return undefined;
    }

    async refreshToken(refreshToken: string) {
        const tokenSet = this.getTokensSetThatHaveRefreshToken(refreshToken);

        if (!tokenSet) throw new AuthenticationException('invalid refresh token');

        await tokenSet.refresh(refreshToken);

        return tokenSet;
    }

    private getTokensSetThatHaveRefreshToken(refresh: string): TokensSet | undefined {
        for (const token of this.tokens) {
            if (token.refreshTokenEquals(refresh)) {
                return token;
            }
        }

        for (const client of this.clients) {
            if (client.haveRefreshToken(refresh)) {
                return client.getTokens()!;
            }
        }

        return undefined;
    }

    async revokeToken(accessToken: string) {
        const isTokenValid = await this.haveValidToken(accessToken);

        if (!isTokenValid) throw new AuthenticationException('invalid token');

        for (const client of this.clients) {
            if (client.haveAccessToken(accessToken)) {
                return client.revokeTokens();
            }
        }

        this.tokens = this.tokens.filter(set => !set.accessTokenEquals(accessToken));
    }

    private getClientById(id: string) {
        for (const client of this.clients) {
            if (client.idEqual(id)) return client;
        }

        return undefined;
    }
}

export { User };
