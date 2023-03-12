# deno-argon2-wasm

[![releases](https://img.shields.io/github/release/vwerkku/deno-argon2-wasm)](https://github.com/vwerkku/deno-argon2-wasm/releases)
[![build](https://github.com/vwerkku/deno-argon2-wasm/actions/workflows/build.yml/badge.svg)](https://github.com/vwerkku/deno-argon2-wasm/actions/workflows/build.yml)
[![license](https://img.shields.io/github/license/vwerkku/deno-argon2-wasm)](https://github.com/vwerkku/deno-argon2-wasm/blob/master/LICENSE)


This library provides support for the Argon2 password hashing algorithm in Deno. The binding are written in Rust and compiled to WebAssembly.

## Usage

```typescript
import { hash, verify } from 'https://deno.land/x/argon2_wasm/mod.ts';

// Hash a password and get the encoded hash.
// The salt is automatically generated.
const hashedPassword = hash('hunter2');

// Verify password against encoded hash.
const isPasswordValid = verify('hunter2', hashedPassword);
```

## Maintainers

- Victor Wernér ([@vwerkku](https://github.com/vwerkku))

## License

Copyright (c) 2023 Victor Wernér. Licensed under the MIT license.

See [LICENSE](LICENSE) for more details.
