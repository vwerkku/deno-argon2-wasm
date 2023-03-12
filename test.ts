import { assert } from 'https://deno.land/std@0.178.0/testing/asserts.ts';
import { algorithm, hash, Params, verify, version } from './mod.ts';

const baseParameters = {
    memoryCost: 16,
    timeCost: 4,
    parallelismCost: 1,
    outputLength: 32,
} satisfies Partial<Params>;

Deno.test('Argon version V0x10', async (test) => {
    const parameters = {
        ...baseParameters,
        version: version.V0x10,
    };

    await test.step('argon2d algorithm', () => {
        const output = hash('password', {
            algorithm: algorithm.argon2d,
            ...parameters,
        });

        assert(verify('password', output) === true);
    });

    await test.step('argon2i algorithm', () => {
        const output = hash('password', {
            algorithm: algorithm.argon2i,
            ...parameters,
        });

        assert(verify('password', output) === true);
    });

    await test.step('argon2id algorithm', () => {
        const output = hash('password', {
            algorithm: algorithm.argon2id,
            ...parameters,
        });

        assert(verify('password', output) === true);
    });
});

Deno.test('Argon version V0x13', async (test) => {
    const parameters = {
        ...baseParameters,
        version: version.V0x13,
    };

    await test.step('argon2d algorithm', () => {
        const output = hash('password', {
            algorithm: algorithm.argon2d,
            ...parameters,
        });

        assert(verify('password', output) === true);
    });

    await test.step('argon2i algorithm', () => {
        const output = hash('password', {
            algorithm: algorithm.argon2i,
            ...parameters,
        });

        assert(verify('password', output) === true);
    });

    await test.step('argon2id algorithm', () => {
        const output = hash('password', {
            algorithm: algorithm.argon2id,
            ...parameters,
        });

        assert(verify('password', output) === true);
    });
});
