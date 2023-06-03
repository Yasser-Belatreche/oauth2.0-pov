import { expect } from 'chai';

import { aUser } from './fixtures/user';

import { AuthManagerFactory } from '../main/auth-manager-factory';
import { AuthenticationException } from '../main/core/exception/authentication-exception';

describe('end user credentials grant', () => {
    const manager = AuthManagerFactory.Instance();

    it('should be able to generate a unique access token & refresh token for each user', async () => {
        const tokens1 = await manager.generateTokensFor(aUser());
        const tokens2 = await manager.generateTokensFor(aUser());

        expect(tokens1.accessToken).to.not.equal(tokens2.accessToken);
        expect(tokens1.refreshToken).to.not.equal(tokens2.refreshToken);
    });

    it('should not accept invalid access tokens', async () => {
        try {
            await manager.decodeToken('invalid token bla bla');
            expect.fail('should throw an exception');
        } catch (e) {
            expect(e).to.be.instanceof(AuthenticationException);
        }
    });

    it('should be able to decode the token and return the associated user', async () => {
        const user = aUser();
        const { accessToken } = await manager.generateTokensFor(user);

        const { user: returned } = await manager.decodeToken(accessToken);

        expect(returned).to.deep.include(user);
    });

    it('should be able to generate two different tokens for the same user', async () => {
        const user = aUser();

        const tokens1 = await manager.generateTokensFor(user);

        await wait(1);

        const tokens2 = await manager.generateTokensFor(user);

        expect(tokens1).to.not.deep.equal(tokens2);
    });

    it('should be able to refresh an access token', async () => {
        const { refreshToken, accessToken: old } = await manager.generateTokensFor(aUser());

        await wait(1);

        const tokens = await manager.refreshToken(refreshToken);

        expect(tokens.accessToken).to.not.equal(old);
    });

    it('should not be able to refresh an access token by passing an invalid refresh token', async () => {
        try {
            await manager.refreshToken('invalid');
            expect.fail('should throw an exception');
        } catch (e) {
            expect(e).to.be.instanceof(AuthenticationException);
        }
    });

    it('should be able to revoke an access token and revoke the refresh token associated with it', async () => {
        const { accessToken, refreshToken } = await manager.generateTokensFor(aUser());

        await manager.revokeToken(accessToken);

        try {
            await manager.decodeToken(accessToken);
            expect.fail('should throw an exception');
        } catch (e) {
            expect(e).to.be.instanceof(AuthenticationException);
        }

        try {
            await manager.refreshToken(refreshToken);
            expect.fail('should throw an exception');
        } catch (e) {
            expect(e).to.be.instanceof(AuthenticationException);
        }
    });

    async function wait(time: number): Promise<void> {
        return await new Promise(resolve => {
            setTimeout(resolve, time);
        });
    }
});
