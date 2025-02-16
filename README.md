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
import { AESGCMEncryption } from 'easy-cipher-mate';

const encryption = new AESGCMEncryption();
const config = new AESGCMEncryptionConfigFromEnv('yourpassword');
const service = new EncryptionService(encryption, config);

// Encrypting a file
const encryptedData = await service.encryptFile(fileBuffer);

// Decrypting a file
const decryptedData = await service.decryptFile(encryptedBuffer);
```

## Contributing
Feel free to open issues or pull requests. For more information on how to contribute, please visit the [contribution guidelines](CONTRIBUTING.md).

## License
ISC License. See [LICENSE](LICENSE) for more details.
```
