import * as crypto from 'crypto';

class AuthorizationCode {
    static Generate() {
        const expirationDate = new Date();
        expirationDate.setMinutes(expirationDate.getMinutes() + 5);

        return new AuthorizationCode(getUniqueCode(), expirationDate);
    }

    static FromState(state: AuthorizationCode['state']) {
        return new AuthorizationCode(state.value, state.expirationDate);
    }

    private constructor(private readonly value: string, private readonly expirationDate: Date) {}

    get state() {
        return {
            value: this.value,
            expirationDate: this.expirationDate,
        };
    }

    getValue() {
        return this.value;
    }

    isValidAndEquals(another: string) {
        if (this.value !== another) return false;

        return !this.isExpired();
    }

    private isExpired() {
        return this.expirationDate.getTime() < Date.now();
    }
}

const getUniqueCode = () => {
    const salt = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha1');

    hash.update(salt);

    const key = hash.digest().subarray(0, 32);

    return generateRandomString(100, key);
};

function generateRandomString(length: number, key: Buffer) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';

    for (let i = 0; i < length; i++) {
        const randomIndex = key[i % key.length] % characters.length;
        result += characters.charAt(randomIndex);
    }

    return result;
}
export { AuthorizationCode };
