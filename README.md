# easy-cipher-mate

## Overview
`easy-cipher-mate` is a CLI tool and library for encrypting and decrypting files or text. It supports two encryption algorithms: AES-GCM and ChaCha20-Poly1305. It can be used both in the terminal as a command-line tool and programmatically by importing the package into your code.

## Installation

### With npm
```bash
npm install easy-cipher-mate
```

### With yarn
```bash
yarn add easy-cipher-mate
```

## CLI Usage

### Encrypt a file
```bash
easy-cipher-mate encrypt-file -i input.txt -o output.txt -p yourpassword -a aes-gcm
```

### Decrypt a file
```bash
easy-cipher-mate decrypt-file -i encrypted.txt -o decrypted.txt -p yourpassword -a aes-gcm
```

### Encrypt a text file line by line
```bash
easy-cipher-mate encrypt-text-file -f input.txt -p yourpassword -a aes-gcm
```

### Decrypt a text file line by line
```bash
easy-cipher-mate decrypt-text-file -f encrypted.txt -p yourpassword -a aes-gcm
```

## Programmatic Usage

```ts
import { assert } from 'console';
import {
    // Algorithm AES-GCM
    AESGCMEncryption,
    IAESGCMEncryptionConfig,
    AESGCMEncryptionConfigFromEnv,
    AESGCMEncryptionConfigFromJSON,
    AESGCMEncryptionConfigFromJSONFile,
    // Algorithm ChaCha20-Poly1305
    ChaCha20Poly1305Encryption,
    IChaCha20Poly1305EncryptionConfig,
    ChaCha20Poly1305EncryptionConfigFromEnv,
    // General service
    EncryptionService,
    EncryptionResult,
    // utils
    deriveStringToUint8Array,
    deriveStringToBuffer,
} from '../easy-cipher-mate';

// Algorithm AES-GCM
const password1 = 'yourpassword';
const salt1 = deriveStringToUint8Array('yoursalt', 16);  // length could be any length
const iv1 = deriveStringToUint8Array('youriv', 16);  // length could be any length

const algo1 = new AESGCMEncryption();
// For `AESGCMEncryptionConfigFromEnv`, you can pass the following environment variables:
// - ECM_AESGCM_PASSWORD: The password to use for encryption.
// - ECM_AESGCM_SALT: The salt to use for encryption.
// - ECM_AESGCM_IV: The initialization vector to use for encryption.
const config1 = new AESGCMEncryptionConfigFromEnv(password1, salt1, iv1);
// If password, salt and iv are not provided, it will use values from environment variables.
const _config1 = new AESGCMEncryptionConfigFromEnv();
const service1 = new EncryptionService(algo1, config1);

// encrypt and decrypt
const data1 = 'Hello World';
const encrypted1 = await service1.encryptText(data1);
const decrypted1 = await service1.decryptText(encrypted1.data);
assert(decrypted1 === data1);

// Algorithm ChaCha20-Poly1305
const password2 = 'yourpassword';
const salt2 = deriveStringToBuffer('yoursalt', 16);  // length could be any length
const nouce2 = deriveStringToBuffer('yournounce', ChaCha20Poly1305Encryption.NONCE_LENGTH);

const algo2 = new ChaCha20Poly1305Encryption();
// For `ChaCha20Poly1305EncryptionConfigFromEnv`, you can pass the following environment variables:
// - ECM_CHACHA20_PASSWORD: The password to use for encryption.
// - ECM_CHACHA20_SALT: The salt to use for encryption.
// - ECM_CHACHA20_NONCE: The nonce to use for encryption.
const config2 = new ChaCha20Poly1305EncryptionConfigFromEnv(password2, salt2, nouce2);
// If password, salt and nonce are not provided, it will use values from environment variables.
const _config2 = new ChaCha20Poly1305EncryptionConfigFromEnv();
const service2 = new EncryptionService(algo2, config2);

// You can also Implement your own config class.
class MyConfig implements IChaCha20Poly1305EncryptionConfig {
    password: string;
    salt: Buffer;
    nonce: Buffer;

    constructor(
        ...
    ) {
        ...
    }
}
```

## Contributing
Feel free to open issues or pull requests. For more information on how to contribute, please visit the [contribution guidelines](CONTRIBUTING.md).

## License
ISC License. See [LICENSE](LICENSE) for more details.

