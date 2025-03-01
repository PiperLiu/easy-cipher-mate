import iconv from 'iconv-lite';

/**
 * Supported text encodings for encryption/decryption
 */
export type TextEncoding = 'utf-8' | 'ascii' | 'utf16le' | 'base64' | 'hex' | 'binary' | 'latin1';

/**
 * Encodes a string to ArrayBuffer using the specified encoding
 * @param text The text to encode
 * @param encoding The encoding to use (defaults to utf-8)
 * @returns ArrayBuffer containing the encoded text
 */
export function encodeText(text: string, encoding: TextEncoding = 'utf-8'): ArrayBuffer {
  // 特殊处理 binary（即 latin1）
  if (encoding === 'binary') encoding = 'latin1';

  // 处理 base64/hex 的特殊逻辑
  if (encoding === 'base64' || encoding === 'hex') {
    const utf8Buffer = iconv.encode(text, 'utf8');
    const encodedStr = Buffer.from(utf8Buffer).toString(encoding);
    return iconv.encode(encodedStr, 'latin1').buffer;
  }

  // 其他编码使用 iconv-lite
  try {
    const buffer = iconv.encode(text, encoding);
    return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  } catch {
    throw new Error(`Unsupported encoding: ${encoding}`);
  }
}

/**
 * Decodes an ArrayBuffer to a string using the specified encoding
 * @param buffer The ArrayBuffer to decode
 * @param encoding The encoding to use (defaults to utf-8)
 * @returns The decoded string
 */
export function decodeText(buffer: ArrayBuffer, encoding: TextEncoding = 'utf-8'): string {
  // 特殊处理 binary（即 latin1）
  if (encoding === 'binary') encoding = 'latin1';

  // 处理 base64/hex 的特殊逻辑
  if (encoding === 'base64' || encoding === 'hex') {
    const encodedStr = iconv.decode(Buffer.from(buffer), 'latin1');
    const decodedBuffer = Buffer.from(encodedStr, encoding);
    return iconv.decode(decodedBuffer, 'utf8');
  }

  // 其他编码使用 iconv-lite
  try {
    return iconv.decode(Buffer.from(buffer), encoding);
  } catch {
    throw new Error(`Unsupported encoding: ${encoding}`);
  }
}