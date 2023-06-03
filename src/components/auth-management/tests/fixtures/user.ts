import { faker } from '@faker-js/faker';
import { UserInfo } from '../../main/core/user';

const aUser = (overrides?: UserInfo) => ({
    id: faker.datatype.uuid(),
    role: faker.word.noun(),
    ...overrides,
});

export { aUser };
