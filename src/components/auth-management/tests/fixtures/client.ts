import { faker } from '@faker-js/faker';

const aClient = (overrides?: { label: string; redirectUrl: string }) => ({
    label: faker.datatype.uuid(),
    redirectUrl: faker.internet.url(),
    ...overrides,
});

export { aClient };
