import * as crypto from 'crypto';

import { TokensSet } from './tokens-set';
import { AuthorizationCode } from './authorization-code';
import { AuthenticationException } from './exception/authentication-exception';

export interface ClientInfo {
    label: string;
    redirectUrl: string;
}

class Client {
    static Generate(info: ClientInfo): Client {
        return new Client(
            crypto.randomUUID(),
            getUniqueSecret(),
            info.label,
            info.redirectUrl,
            [],
            null,
            null,
        );
    }

    static FromState(state: Client['state']) {
        return new Client(
            state.id,
            state.secret,
            state.label,
            state.redirectUrl,
            state.scope,
            state.tokens ? TokensSet.FromState(state.tokens) : null,
            state.code ? AuthorizationCode.FromState(state.code) : null,
        );
    }

    private constructor(
        private readonly id: string,
        private readonly secret: string,
        private readonly label: string,
        private readonly redirectUrl: string,
        private scope: string[],
        private tokens: TokensSet | null,
        private code: AuthorizationCode | null,
    ) {}

    get state() {
        return {
            id: this.id,
            secret: this.secret,
            label: this.label,
            redirectUrl: this.redirectUrl,
            scope: this.scope,
            tokens: this.tokens?.state,
            code: this.code?.state,
        };
    }

    getBasicInfo() {
        return {
            id: this.id,
            secret: this.secret,
            label: this.label,
            scope: this.scope,
            redirectUrl: this.redirectUrl,
        };
    }

    idEqual(another: string) {
        return this.id === another;
    }

    getTokens(): TokensSet | null {
        return this.tokens;
    }

    generateRedirectUrl(redirectUrl: string, state: string, scope: string[]): string {
        if (redirectUrl !== this.redirectUrl)
            throw new AuthenticationException('redirect url mismatch');

        this.code = AuthorizationCode.Generate();
        this.scope = scope;

        return `${this.redirectUrl}?code=${this.code.getValue()}&state=${state}`;
    }

    async generateTokens(code: string, redirectUrl: string, secret: string) {
        if (secret !== this.secret) throw new AuthenticationException('invalid client');
        if (redirectUrl !== this.redirectUrl) throw new AuthenticationException('invalid client');
        if (!this.code) throw new AuthenticationException('invalid client code');
        if (!this.code.isValidAndEquals(code))
            throw new AuthenticationException('invalid client code');

        this.tokens = await TokensSet.GenerateFor(this.id);
        this.code = null;

        return this.tokens;
    }

    async isAccessTokenStillValid() {
        return Boolean(await this.tokens?.isAccessTokenStillValid());
    }

    revokeTokens() {
        this.tokens = null;
    }

    haveAccessToken(token: string) {
        return !!this.tokens?.accessTokenEquals(token);
    }

    haveRefreshToken(token: string) {
        return !!this.tokens?.refreshTokenEquals(token);
    }
}

const getUniqueSecret = () => {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.createHash('sha1');

    hash.update(salt);

    const key = hash.digest().subarray(0, 16);

    return key.toString('hex');
};

export { Client };
