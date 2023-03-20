import { encode as base64encode } from "std/encoding/base64.ts";

// Compile with cargo.
await Deno.run({
    cmd: [
        "cargo",
        "build",
        "--release",
        "--target",
        "wasm32-unknown-unknown",
    ]
}).status();

// Run wasm-opt to optimize for an even smaller file size.
await Deno.run({
    cmd: [
        "wasm-opt",
        "-O3",
        "-o",
        "./wasm/argon2.wasm",
        "./target/wasm32-unknown-unknown/release/argon2.wasm",
    ]
}).status();

// Convert the wasm into base64.
const wasm = await Deno.readFile('./wasm/argon2.wasm');
const wasmb64 = base64encode(wasm);

// This is a rather crappy approach but we can't do much
// better with Deno as `deno cache` doesn't download
// non-ts files, such as wasm files.
const output = `
import { decode as base64decode } from "std/encoding/base64.ts";
export const argon2wasm = base64decode("${wasmb64}");`;

const encoder = new TextEncoder();
Deno.writeFile('./wasm/argon2.ts', encoder.encode(output), {
    create: true
});
