import * as base64 from 'https://deno.land/std@0.178.0/encoding/base64.ts';
import {
    crypto,
    toHashString,
} from 'https://deno.land/std@0.178.0/crypto/mod.ts';

import {
    allocate,
    deallocate,
    hashRaw,
    memory,
    verifyRaw,
} from './wasm/mod.ts';

export const version = {
    /**
     * Version 16, performs overwrite internally
     */
    V0x10: 0x10,

    /**
     * Version 19, performs XOR internally
     */
    V0x13: 0x13,
} as const;

export const algorithm = {
    /**
     * Optimized against GPU cracking attacks but vulnerable to side-channel attacks.
     */
    argon2d: 0,

    /**
     * Optimized to resist side-channel attacks.
     */
    argon2i: 1,

    /**
     * Hybrid that mixes Argon2i and Argon2d passes.
     */
    argon2id: 2,
} as const;

export interface Params {
    /**
     * {@link algorithm}.
     */
    algorithm: typeof algorithm[keyof typeof algorithm];

    /**
     * Memory size in powers of 2.
     *
     * E.g: 16 = 2^16 = 65536 bytes
     */
    memoryCost: number;

    /**
     * Number of iterations.
     */
    timeCost: number;

    /**
     * Degree of parallelism.
     */
    parallelismCost: number;

    /**
     * {@link version}.
     */
    version: typeof version[keyof typeof version];

    /**
     * Output length of the digest in bytes.
     */
    outputLength: number;
}

/**
 * Transfers data from JavaScript into WASM memory.
 */
function writeToWasm(data: Uint8Array): [
    pointer: number,
    length: number,
] {
    const pointer = allocate(data.length);
    const wasmMemory = new Uint8Array(memory.buffer, pointer, data.length);
    wasmMemory.set(data);

    return [pointer, data.length];
}

/**
 * Transfers data from WASM memory into JavaScript.
 */
function readFromWasm(pointer: number, length: number): Uint8Array {
    const wasmMemory = new Uint8Array(memory.buffer, pointer, length);
    return wasmMemory.slice(0, length);
}

/**
 * Default parameters to use for Argon2 hashing.
 */
function defaultParams(): Params {
    return {
        algorithm: algorithm.argon2id,
        memoryCost: 12,
        timeCost: 3,
        parallelismCost: 1,
        version: version.V0x13,
        outputLength: 32,
    };
}

/**
 * Helper that calls the Rust binding for hashing.
 *
 * Allocates and deallocates memory where necessary.
 */
function hashInternal(
    password: Uint8Array,
    salt: Uint8Array,
    params: Params,
): Uint8Array {
    const [passwordPointer, passwordLength] = writeToWasm(password);
    const [saltPointer, saltLength] = writeToWasm(salt);

    const pointer = hashRaw(
        passwordPointer,
        passwordLength,
        saltPointer,
        saltLength,
        params.algorithm,
        params.memoryCost,
        params.timeCost,
        params.parallelismCost,
        params.outputLength,
        params.version,
    );

    const slice = readFromWasm(pointer, params.outputLength);
    deallocate(passwordPointer, passwordLength);
    deallocate(saltPointer, saltLength);
    deallocate(pointer, params.outputLength);

    return slice;
}

/**
 * Helper that calls the Rust binding for verifying.
 *
 * Allocates and deallocates memory where necessary.
 */
function verifyInternal(password: Uint8Array, hash: Uint8Array): boolean {
    const [passwordPointer, passwordLength] = writeToWasm(password);
    const [hashPointer, hashLength] = writeToWasm(hash);

    const result = verifyRaw(
        passwordPointer,
        passwordLength,
        hashPointer,
        hashLength,
    );

    deallocate(passwordPointer, passwordLength);
    deallocate(hashPointer, hashLength);

    return Boolean(result);
}

/**
 * Hashes a password with argon2 and returns
 * the encoded string.
 *
 * The encoded string contains everything needed
 * to verify the hash, including the algorithm, version,
 * parameters, salt and digest.
 *
 * Example of encoded hash using the default parameters:
 * - $argon2id$v=19$m=12,t=3,p=1$WXVCbmxpcm03aTBpYlh1eA$47fohumcB4HSKecoOg4fJiTyHRgcemqw8Q7SUk1Oyvg
 */
export function hash(
    password: string,
    partialParams?: Partial<Params>,
): string {
    const params = Object.assign(defaultParams(), partialParams);
    const encoder = new TextEncoder();

    // Generate a psuedo random salt
    const salt = toHashString(crypto.subtle.digestSync(
        'SHA-256',
        crypto.getRandomValues(new Uint8Array(16)),
    )).slice(0, 16);

    const digest = hashInternal(
        encoder.encode(password),
        encoder.encode(salt),
        params,
    );

    // Encode salt and digest as base 64 without padding
    const saltb64 = base64.encode(salt).replace(/\=/gm, '');
    const digestb64 = base64.encode(digest).replace(/\=/gm, '');

    const algo = Object.keys(algorithm).find((key) => {
        return algorithm[key as keyof typeof algorithm] === params.algorithm;
    });

    return `
        $${algo}
        $v=${params.version}$
        m=${1 << params.memoryCost},
        t=${params.timeCost},
        p=${params.parallelismCost}
        $${saltb64}
        $${digestb64}
    `.replace(/(\n|\r|\r\n|\s+)/gm, '');
}

/**
 * Verifies that a encoded argon2 string is valid.
 */
export function verify(password: string, hash: string): boolean {
    const encoder = new TextEncoder();

    return verifyInternal(encoder.encode(password), encoder.encode(hash));
}
