import { expect } from 'chai';

import { aUser } from './fixtures/user';
import { aClient } from './fixtures/client';

import { AuthManagerFactory } from '../main/auth-manager-factory';
import { AuthenticationException } from '../main/core/exception/authentication-exception';

describe('authorization code grant', () => {
    const manager = AuthManagerFactory.Instance();

    it('should be able to generate some unique id and secret for each client of a specific user', async () => {
        const user = aUser();
        const client = aClient();

        const clientCredentials1 = await manager.generateClient(user, client);
        const clientCredentials2 = await manager.generateClient(user, client);

        expect(clientCredentials1.id).to.not.equal(clientCredentials2.id);
        expect(clientCredentials1.secret).to.not.equal(clientCredentials2.secret);
    });

    it('should be able to retreive the user clients', async () => {
        const user = aUser();

        const client1 = aClient();
        const clientCredentials1 = await manager.generateClient(user, client1);

        const client2 = aClient();
        const clientCredentials2 = await manager.generateClient(user, client2);

        const clients = await manager.getClientsOf(user.id);

        expect(clients).to.have.length(2);

        expect(clients).to.deep.includes({ ...client1, ...clientCredentials1 });
        expect(clients).to.deep.includes({ ...client2, ...clientCredentials2 });
    });

    it('should not generate authorization code for a client that does not exists', async () => {
        const user = aUser();

        try {
            await manager.generateClientRedirectUrl(user, {
                clientId: 'not-exists',
                redirectUrl: '',
                state: '',
                scope: [],
            });

            expect.fail('should throw an exception');
        } catch (e) {
            expect(e).to.be.instanceof(AuthenticationException);
        }
    });

    it('should not generate authorization code if the passed client does not match the registered redirect url', async () => {
        const user = aUser();

        const client = aClient();

        const credentials = await manager.generateClient(user, client);

        try {
            await manager.generateClientRedirectUrl(user, {
                clientId: credentials.id,
                redirectUrl: 'not same as registered',
                state: '',
                scope: [],
            });

            expect.fail('should throw an exception');
        } catch (e) {
            expect(e).to.be.instanceof(AuthenticationException);
        }
    });

    it('should return the redirect url containing the authorization code along side with passed state', async () => {
        const user = aUser();

        const client = aClient();

        const credentials = await manager.generateClient(user, client);

        const { redirectUrl } = await manager.generateClientRedirectUrl(user, {
            clientId: credentials.id,
            redirectUrl: credentials.redirectUrl,
            state: 'some-state',
            scope: [],
        });

        const url = new URL(redirectUrl);

        const authorizationCode = url.searchParams.get('code');
        const state = url.searchParams.get('state');

        expect(authorizationCode).to.be.a('string');
        expect(state).to.equal('some-state');
    });

    it('should generate unique authorization codes per client', async () => {
        const user = aUser();

        const client1 = aClient();
        const credentials1 = await manager.generateClient(user, client1);

        const client2 = aClient();
        const credentials2 = await manager.generateClient(user, client2);

        const { redirectUrl: redirectUrl1 } = await manager.generateClientRedirectUrl(user, {
            clientId: credentials1.id,
            redirectUrl: credentials1.redirectUrl,
            state: 'some-state',
            scope: [],
        });

        const { redirectUrl: redirectUrl2 } = await manager.generateClientRedirectUrl(user, {
            clientId: credentials2.id,
            redirectUrl: credentials2.redirectUrl,
            state: 'some-state',
            scope: [],
        });

        const url1 = new URL(redirectUrl1);
        const url2 = new URL(redirectUrl2);

        expect(url1.searchParams.get('code')).to.not.equal(url2.searchParams.get('code'));
    });

    it('when trying to generate the client tokens, the client should be registered', async () => {
        const user = aUser();

        try {
            await manager.generateClientTokens(user, {
                clientId: 'not-exist',
                clientSecret: 'secret',
                code: 'some-code',
                redirectUrl: 'url',
            });
            expect.fail('should throw an exception');
        } catch (e) {
            expect(e).to.be.instanceof(AuthenticationException);
        }
    });

    it('when trying to generate the client tokens, the client secret should be correct', async () => {
        const user = aUser();
        const client = aClient();

        const credentials = await manager.generateClient(user, client);

        try {
            await manager.generateClientTokens(user, {
                clientId: credentials.id,
                clientSecret: 'secret',
                code: 'some-code',
                redirectUrl: 'url',
            });
            expect.fail('should throw an exception');
        } catch (e) {
            expect(e).to.be.instanceof(AuthenticationException);
        }
    });

    it('when trying to generate the client tokens, the redirect url should be correct', async () => {
        const user = aUser();
        const client = aClient();

        const credentials = await manager.generateClient(user, client);

        try {
            await manager.generateClientTokens(user, {
                clientId: credentials.id,
                clientSecret: credentials.secret,
                code: 'some-code',
                redirectUrl: 'url',
            });
            expect.fail('should throw an exception');
        } catch (e) {
            expect(e).to.be.instanceof(AuthenticationException);
        }
    });

    it('when trying to generate the client tokens, the code should be correct', async () => {
        const user = aUser();
        const client = aClient();

        const credentials = await manager.generateClient(user, client);

        try {
            await manager.generateClientTokens(user, {
                clientId: credentials.id,
                clientSecret: credentials.secret,
                code: 'some-code',
                redirectUrl: credentials.redirectUrl,
            });
            expect.fail('should throw an exception');
        } catch (e) {
            expect(e).to.be.instanceof(AuthenticationException);
        }
    });

    it('should be able to generate the redirect url for a client containing the authorization code and then use that authorization code to generate tokens for the client', async () => {
        const user = aUser();
        const client = aClient();

        const credentials = await manager.generateClient(user, client);

        const { redirectUrl } = await manager.generateClientRedirectUrl(user, {
            clientId: credentials.id,
            redirectUrl: credentials.redirectUrl,
            state: 'some-state',
            scope: [],
        });

        const url = new URL(redirectUrl);
        const code = url.searchParams.get('code')!;

        const tokens = await manager.generateClientTokens(user, {
            code,
            clientId: credentials.id,
            clientSecret: credentials.secret,
            redirectUrl: credentials.redirectUrl,
        });

        expect(tokens.accessToken).to.be.a('string');
        expect(tokens.refreshToken).to.be.a('string');
    });

    it('should not be able to use the code more than once', async () => {
        const user = aUser();
        const client = aClient();

        const credentials = await manager.generateClient(user, client);

        const { redirectUrl } = await manager.generateClientRedirectUrl(user, {
            clientId: credentials.id,
            redirectUrl: credentials.redirectUrl,
            state: 'some-state',
            scope: [],
        });

        const url = new URL(redirectUrl);
        const code = url.searchParams.get('code')!;

        await manager.generateClientTokens(user, {
            code,
            clientId: credentials.id,
            clientSecret: credentials.secret,
            redirectUrl: credentials.redirectUrl,
        });

        try {
            await manager.generateClientTokens(user, {
                code,
                clientId: credentials.id,
                clientSecret: credentials.secret,
                redirectUrl: credentials.redirectUrl,
            });

            expect.fail('should throw an exception');
        } catch (e) {
            expect(e).to.be.instanceof(AuthenticationException);
        }
    });

    it('should be able to decode the token and return the associated client', async () => {
        const user = aUser();
        const client = aClient();

        const credentials = await manager.generateClient(user, client);

        const { redirectUrl } = await manager.generateClientRedirectUrl(user, {
            clientId: credentials.id,
            redirectUrl: credentials.redirectUrl,
            state: 'some-state',
            scope: ['scope2'],
        });

        const url = new URL(redirectUrl);
        const code = url.searchParams.get('code')!;

        const { accessToken } = await manager.generateClientTokens(user, {
            code,
            clientId: credentials.id,
            clientSecret: credentials.secret,
            redirectUrl: credentials.redirectUrl,
        });

        const returned = await manager.decodeToken(accessToken);

        expect(returned).to.deep.equal({
            user,
            client: {
                id: credentials.id,
                scope: ['scope2'],
            },
        });
    });

    it('should be able to refresh an access token of the client', async () => {
        const user = aUser();
        const client = aClient();

        const credentials = await manager.generateClient(user, client);

        const { redirectUrl } = await manager.generateClientRedirectUrl(user, {
            clientId: credentials.id,
            redirectUrl: credentials.redirectUrl,
            state: 'some-state',
            scope: ['scope2'],
        });

        const url = new URL(redirectUrl);
        const code = url.searchParams.get('code')!;

        const { accessToken: old, refreshToken } = await manager.generateClientTokens(user, {
            code,
            clientId: credentials.id,
            clientSecret: credentials.secret,
            redirectUrl: credentials.redirectUrl,
        });

        const tokens = await manager.refreshToken(refreshToken);

        expect(tokens.accessToken).to.not.equal(old);
    });

    it('should be able to revoke an access token of a client and revoke the refresh token associated with it', async () => {
        const user = aUser();
        const client = aClient();

        const credentials = await manager.generateClient(user, client);

        const { redirectUrl } = await manager.generateClientRedirectUrl(user, {
            clientId: credentials.id,
            redirectUrl: credentials.redirectUrl,
            state: 'some-state',
            scope: ['scope2'],
        });

        const url = new URL(redirectUrl);
        const code = url.searchParams.get('code')!;

        const { accessToken, refreshToken } = await manager.generateClientTokens(user, {
            code,
            clientId: credentials.id,
            clientSecret: credentials.secret,
            redirectUrl: credentials.redirectUrl,
        });

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
});
