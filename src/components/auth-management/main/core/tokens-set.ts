import * as jose from 'jose';
import { AuthenticationException } from './exception/authentication-exception';

// should put it in an env variable
const secret = new TextEncoder().encode(
    'cc7e0d44fd473002f1c42167459001140ec6389b7353f8088f4d9a95f2f596f2',
);

class TokensSet {
    static async GenerateFor(issuer: string): Promise<TokensSet> {
        const now = new Date();

        const accessToken = await new jose.SignJWT({})
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setIssuedAt()
            .setIssuer(issuer)
            .setExpirationTime(now.setHours(now.getHours() + 2))
            .sign(secret);

        const refreshToken = await new jose.SignJWT({})
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setIssuedAt()
            .setIssuer(issuer)
            .setExpirationTime(now.setDate(now.getDate() + 7))
            .sign(secret);

        return new TokensSet(accessToken, refreshToken, null, issuer);
    }

    static async GenerateWithIdentity(
        issuer: string,
        identity: Record<string, string>,
    ): Promise<TokensSet> {
        const now = new Date();

        const accessToken = await new jose.SignJWT({})
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setIssuedAt()
            .setIssuer(issuer)
            .setExpirationTime(now.setHours(now.getHours() + 2))
            .sign(secret);

        const idToken = await new jose.SignJWT(identity)
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setIssuedAt()
            .setIssuer(issuer)
            .sign(secret);

        const refreshToken = await new jose.SignJWT({})
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setIssuedAt()
            .setIssuer(issuer)
            .setExpirationTime(now.setDate(now.getDate() + 7))
            .sign(secret);

        return new TokensSet(accessToken, refreshToken, idToken, issuer);
    }

    static FromState(state: TokensSet['state']) {
        return new TokensSet(state.accessToken, state.refreshToken, state.idToken, state.issuer);
    }

    private constructor(
        private accessToken: string,
        private readonly refreshToken: string,
        private readonly idToken: string | null,
        private readonly issuer: string,
    ) {}

    get state() {
        return {
            accessToken: this.accessToken,
            refreshToken: this.refreshToken,
            idToken: this.idToken,
            issuer: this.issuer,
        };
    }

    get values() {
        return {
            accessToken: this.accessToken,
            refreshToken: this.refreshToken,
            idToken: this.idToken,
        };
    }

    accessTokenEquals(another: string) {
        return this.accessToken === another;
    }

    refreshTokenEquals(another: string) {
        return this.refreshToken === another;
    }

    async isAccessTokenStillValid(): Promise<boolean> {
        try {
            await jose.jwtVerify(this.accessToken, secret, { algorithms: ['HS256'], typ: 'JWT' });

            return true;
        } catch (e) {
            return false;
        }
    }

    async refresh(refreshToken: string) {
        if (!this.refreshTokenEquals(refreshToken))
            throw new AuthenticationException('invalid refresh token');

        try {
            await jose.jwtVerify(refreshToken, secret, { algorithms: ['HS256'], typ: 'JWT' });
        } catch (e) {
            throw new AuthenticationException('invalid refresh token');
        }

        const now = new Date();

        this.accessToken = await new jose.SignJWT({})
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setIssuedAt()
            .setIssuer(this.issuer)
            .setExpirationTime(now.setHours(now.getHours() + 2))
            .sign(secret);
    }
}

export { TokensSet };
