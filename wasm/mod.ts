const __dirname = new URL('./', import.meta.url).pathname;

const wasm = await Deno.readFile(`${__dirname}argon2.wasm`);
const { instance } = await WebAssembly.instantiate(wasm, {
    env: {
        panic: (pointer: number, length: number) => {
            const message = new TextDecoder().decode(
                new Uint8Array(memory.buffer, pointer, length),
            );

            throw new Error(message);
        },
    },
});

const memory = instance.exports.memory as WebAssembly.Memory;
const init = instance.exports.init as () => void;
const allocate = instance.exports.allocate as (size: number) => number;
const deallocate = instance.exports.deallocate as (
    ptr: number,
    size: number,
) => void;

const hashRaw = instance.exports.hash as (
    passwordPtr: number,
    passwordLen: number,
    saltPtr: number,
    saltLen: number,
    algorithm: number,
    memoryCost: number,
    timeCost: number,
    parallelismCost: number,
    outputLength: number,
    version: number,
) => number;

const verifyRaw = instance.exports.verify as (
    passwordPtr: number,
    passwordLen: number,
    hashPtr: number,
    hashLen: number,
) => boolean;

init();

export { allocate, deallocate, hashRaw, memory, verifyRaw };
