# easy-cipher-mate

A library and CLI tool providing easy-to-use encryption capabilities for Node.js and browser environments.

## Features

- Multiple encryption algorithms:
  - AES-GCM for robust symmetric encryption
  - ChaCha20-Poly1305 for high-performance encryption
- Text encoding options for multi-language support
- File encryption capabilities
- Line-by-line text file encryption
- Environment variable configuration
- Simple API for encryption and decryption

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

Options:
- `-i, --input <path>`: Input file path (required)
- `-o, --output <path>`: Output file path (required)
- `-p, --password <string>`: Encryption password (required)
- `-a, --algorithm <string>`: Encryption algorithm - either 'aes-gcm' (default) or 'chacha20-poly1305'

### Decrypt a file
```bash
easy-cipher-mate decrypt-file -i encrypted.txt -o decrypted.txt -p yourpassword -a aes-gcm
```

Options:
- `-i, --input <path>`: Input file path (required)
- `-o, --output <path>`: Output file path (required)
- `-p, --password <string>`: Decryption password (required)
- `-a, --algorithm <string>`: Decryption algorithm - either 'aes-gcm' (default) or 'chacha20-poly1305'

### Encrypt a text file line by line
```bash
easy-cipher-mate encrypt-text-file -f input.txt -p yourpassword -a aes-gcm -e utf-8
```

Options:
- `-f, --file <path>`: Text file path (required)
- `-p, --password <string>`: Encryption password (required)
- `-a, --algorithm <string>`: Encryption algorithm - either 'aes-gcm' (default) or 'chacha20-poly1305'
- `-e, --encoding <string>`: Text encoding - 'utf-8' (default), 'ascii', 'utf16le', 'base64', 'hex', 'latin1', or 'binary'

### Decrypt a text file line by line
```bash
easy-cipher-mate decrypt-text-file -f encrypted.txt -p yourpassword -a aes-gcm -e utf-8
```

Options:
- `-f, --file <path>`: Text file path (required)
- `-p, --password <string>`: Decryption password (required)
- `-a, --algorithm <string>`: Decryption algorithm - either 'aes-gcm' (default) or 'chacha20-poly1305'
- `-e, --encoding <string>`: Text encoding - 'utf-8' (default), 'ascii', 'utf16le', 'base64', 'hex', 'latin1', or 'binary'

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

### Working with Different Text Encodings

There are two ways to specify the text encoding:

#### 1. In the Configuration Object

```typescript
import { 
  AESGCMEncryption, 
  AESGCMEncryptionConfigFromJSON 
} from 'easy-cipher-mate';

const encryption = new AESGCMEncryption();

// Configure with specific text encoding
const config = new AESGCMEncryptionConfigFromJSON({
  password: 'my-password',
  textEncoding: 'base64' // Set base64 as default encoding for all operations
});

// Encrypt text with base64 encoding (from config)
const encryptedResult = await encryption.encryptText('Secret message', config);

// Decrypt - will use the same encoding from config
const decryptedText = await encryption.decryptText(encryptedResult.data, config);
console.log(decryptedText); // 'Secret message'
```

#### 2. As a Parameter in Method Calls

You can override the encoding set in the configuration by passing an explicit encoding parameter:

```typescript
import { 
  AESGCMEncryption, 
  AESGCMEncryptionConfigFromJSON 
} from 'easy-cipher-mate';

const encryption = new AESGCMEncryption();
const config = new AESGCMEncryptionConfigFromJSON({
  password: 'my-password',
  textEncoding: 'utf-8' // Default is utf-8
});

// Encrypt with hex encoding (overrides the utf-8 from config)
const encryptedResult = await encryption.encryptText('Secret message', config, 'hex');

// Decrypt with hex encoding (must match the encoding used for encryption)
const decryptedText = await encryption.decryptText(encryptedResult.data, config, 'hex');
console.log(decryptedText); // 'Secret message'

// You can mix and match encodings as needed
const textInBase64 = await encryption.encryptText('Another message', config, 'base64');
const decryptedBase64 = await encryption.decryptText(textInBase64.data, config, 'base64');

// The encoding parameter works with the service wrapper too
const service = new EncryptionService(encryption, config);
const encrypted = await service.encryptText('Hello world', 'latin1');
const decrypted = await service.decryptText(encrypted.data, 'latin1');
```

### Working with Different Languages

```typescript
import { 
  AESGCMEncryption, 
  AESGCMEncryptionConfigFromJSON 
} from 'easy-cipher-mate';

const encryption = new AESGCMEncryption();
const config = new AESGCMEncryptionConfigFromJSON({
  password: 'my-password'
});

// Encrypt Chinese text
const chineseText = '你好，世界';
const encryptedChinese = await encryption.encryptText(chineseText, config);
const decryptedChinese = await encryption.decryptText(encryptedChinese.data, config);
console.log(decryptedChinese === chineseText); // true

// Encrypt Japanese text with explicit UTF-16LE encoding
const japaneseText = 'こんにちは世界';
const encryptedJapanese = await encryption.encryptText(japaneseText, config, 'utf16le');
const decryptedJapanese = await encryption.decryptText(encryptedJapanese.data, config, 'utf16le');
console.log(decryptedJapanese === japaneseText); // true
```

### File Encryption

```typescript
import { AESGCMEncryption, AESGCMEncryptionConfigFromJSON } from 'easy-cipher-mate';
import { readFileSync, writeFileSync } from 'fs';

const encryption = new AESGCMEncryption();
const config = new AESGCMEncryptionConfigFromJSON({
  password: 'my-password'
});

// Read file
const fileBuffer = readFileSync('document.pdf');
const arrayBuffer = fileBuffer.buffer.slice(fileBuffer.byteOffset, fileBuffer.byteOffset + fileBuffer.byteLength);

// Encrypt file
const encryptedResult = await encryption.encryptFile(arrayBuffer, config);

// Save encrypted file
writeFileSync('document.pdf.encrypted', Buffer.from(encryptedResult.data));

// Later, to decrypt:
const encryptedFileBuffer = readFileSync('document.pdf.encrypted');
const encryptedArrayBuffer = encryptedFileBuffer.buffer.slice(
  encryptedFileBuffer.byteOffset, 
  encryptedFileBuffer.byteOffset + encryptedFileBuffer.byteLength
);
const decryptedBuffer = await encryption.decryptFile(encryptedArrayBuffer, config);
writeFileSync('document.pdf.decrypted', Buffer.from(decryptedBuffer));

// You can also use the EncryptionService for simpler file operations
const service = new EncryptionService(encryption, config);
await service.encryptFileByName('document.pdf');
await service.decryptFileByName(encryptedResult, 'document.pdf.decrypted');
```

## Line-by-Line Text File Encryption

In addition to encrypting entire files, easy-cipher-mate allows you to encrypt/decrypt text files line by line:

```typescript
import { AESGCMEncryption, AESGCMEncryptionConfigFromJSON, EncryptionService } from 'easy-cipher-mate';
import { readFileSync, writeFileSync } from 'fs';

const encryption = new AESGCMEncryption();
const config = new AESGCMEncryptionConfigFromJSON({
  password: 'my-password'
});

const service = new EncryptionService(encryption, config);
const filePath = 'document.txt';

// Read the file and split into lines
const content = readFileSync(filePath, 'utf-8');
const lines = content.split(/\r?\n/);

// Encrypt each non-empty line
const encryptedLines = await Promise.all(
  lines.map(async line => {
    if (line.trim() === '') return line;
    const result = await service.encryptText(line);
    return Buffer.from(result.data).toString('base64');
  })
);

// Save the encrypted content
writeFileSync(`${filePath}.encrypted`, encryptedLines.join('\n'));

// Later, to decrypt:
const encryptedContent = readFileSync(`${filePath}.encrypted`, 'utf-8');
const encryptedLines2 = encryptedContent.split(/\r?\n/);

// Decrypt each line
const decryptedLines = await Promise.all(
  encryptedLines2.map(async line => {
    if (line.trim() === '') return line;
    const buffer = Buffer.from(line, 'base64');
    return await service.decryptText(buffer);
  })
);

// Save the decrypted content
writeFileSync(`${filePath}.decrypted`, decryptedLines.join('\n'));
```

## API Reference

### Encryption Algorithms

#### AESGCMEncryption

```typescript
encryptText(plaintext: string, config: IAESGCMEncryptionConfig, encoding?: TextEncoding): Promise<EncryptionResult>
decryptText(encryptedData: ArrayBuffer, config: IAESGCMEncryptionConfig, encoding?: TextEncoding): Promise<string>
encryptFile(fileBuffer: ArrayBuffer, config: IAESGCMEncryptionConfig, encoding?: TextEncoding): Promise<EncryptionResult>
decryptFile(encryptedBuffer: ArrayBuffer, config: IAESGCMEncryptionConfig, encoding?: TextEncoding): Promise<ArrayBuffer>
```

#### ChaCha20Poly1305Encryption

```typescript
encryptText(plaintext: string, config: IChaCha20Poly1305EncryptionConfig, encoding?: TextEncoding): Promise<EncryptionResult>
decryptText(encryptedData: ArrayBuffer, config: IChaCha20Poly1305EncryptionConfig, encoding?: TextEncoding): Promise<string>
encryptFile(fileBuffer: ArrayBuffer, config: IChaCha20Poly1305EncryptionConfig, encoding?: TextEncoding): Promise<EncryptionResult>
decryptFile(encryptedBuffer: ArrayBuffer, config: IChaCha20Poly1305EncryptionConfig, encoding?: TextEncoding): Promise<ArrayBuffer>
```

### EncryptionService

A wrapper class that simplifies encryption operations:

```typescript
encryptText(plaintext: string, encoding?: TextEncoding): Promise<EncryptionResult>
decryptText(encryptedData: ArrayBuffer, encoding?: TextEncoding): Promise<string>
encryptFile(fileBuffer: ArrayBuffer, encoding?: TextEncoding): Promise<EncryptionResult>
decryptFile(encryptedBuffer: ArrayBuffer, encoding?: TextEncoding): Promise<ArrayBuffer>
encryptFileByName(fileName: string, encoding?: TextEncoding): Promise<EncryptionResult>
decryptFileByName(encryptedResult: EncryptionResult, fileName: string, encoding?: TextEncoding): Promise<void>
```

## Supported Encodings

The library supports the following text encodings:

- `utf-8` (default): Unicode encoding
- `ascii`: ASCII encoding (7-bit, non-ASCII characters will be lost)
- `utf16le`: UTF-16 Little Endian encoding
- `base64`: Base64 encoding
- `hex`: Hexadecimal encoding
- `latin1`/`binary`: Latin-1 encoding (single byte per character)

## Configuration Options

### Environment Variables

You can configure the encryption using environment variables:

- `ECM_AESGCM_PASSWORD`: The encryption password
- `ECM_AESGCM_SALT`: The salt used for key derivation (optional, base64 encoded)
- `ECM_AESGCM_IV`: The initialization vector (optional, base64 encoded)
- `ECM_CHACHA20_PASSWORD`: The encryption password for ChaCha20-Poly1305
- `ECM_CHACHA20_SALT`: The salt used for key derivation (optional, base64 encoded)
- `ECM_CHACHA20_NONCE`: The nonce (optional, base64 encoded)

For both algorithms:
- `ECM_TEXT_ENCODING`: The text encoding to use (optional, defaults to 'utf-8')

### Configuration via JSON

```typescript
const config = new AESGCMEncryptionConfigFromJSON({
  password: 'my-password',
  salt: 'base64-encoded-salt', // Optional
  iv: 'base64-encoded-iv',     // Optional
  textEncoding: 'utf-8'        // Optional
});
```

### Configuration via JSON File

```typescript
const config = new AESGCMEncryptionConfigFromJSONFile('/path/to/config.json');
```

## Contributing
Feel free to open issues or pull requests. For more information on how to contribute, please visit the [contribution guidelines](CONTRIBUTING.md).

## License
MIT License. See [LICENSE](LICENSE) for more details.
