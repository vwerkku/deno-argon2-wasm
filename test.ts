import { assert } from "std/testing/asserts.ts";
import { algorithm, defaultParams, hash, verify, version } from "./mod.ts";

const baseParameters = defaultParams();

Deno.test("argon2 V0x10", async (test) => {
    const parameters = {
        ...baseParameters,
        version: version.V0x10,
    };

    await test.step("argon2d", () => {
        const output = hash("password", {
            ...parameters,
            algorithm: algorithm.argon2d,
        });

        assert(verify("password", output) === true);
    });

    await test.step("argon2i", () => {
        const output = hash("password", {
            ...parameters,
            algorithm: algorithm.argon2i,
        });

        assert(verify("password", output) === true);
    });

    await test.step("argon2id", () => {
        const output = hash("password", {
            ...parameters,
            algorithm: algorithm.argon2id,
        });

        assert(verify("password", output) === true);
    });
});

Deno.test("argon2 V0x13", async (test) => {
    const parameters = {
        ...baseParameters,
        version: version.V0x13,
    };

    await test.step("argon2d", () => {
        const output = hash("password", {
            ...parameters,
            algorithm: algorithm.argon2d,
        });

        assert(verify("password", output) === true);
    });

    await test.step("argon2i", () => {
        const output = hash("password", {
            ...parameters,
            algorithm: algorithm.argon2i,
        });

        assert(verify("password", output) === true);
    });

    await test.step("argon2id", () => {
        const output = hash("password", {
            ...parameters,
            algorithm: algorithm.argon2id,
        });

        assert(verify("password", output) === true);
    });
});
