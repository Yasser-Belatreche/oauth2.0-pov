import * as jose from 'jose';
import { expect } from 'chai';
import { faker } from '@faker-js/faker';

import { aUser } from './fixtures/user';

import { AuthManagerFactory } from '../main/auth-manager-factory';

describe('identity provider', () => {
    const manager = AuthManagerFactory.Instance();

    it('should be able to generate an id token that contains an identity of the user', async () => {
        const identity = {
            email: faker.internet.email(),
            profilePic: faker.internet.url(),
            fullName: faker.name.fullName(),
        };

        const { idToken } = await manager.generateTokensWithIdentity(aUser(), identity);

        const payload = jose.decodeJwt(idToken);

        expect(payload).to.deep.includes(identity);
    });
});
