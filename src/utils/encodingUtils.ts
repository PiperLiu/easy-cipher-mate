import iconv from 'iconv-lite';

export type TextEncoding = 'utf-8' | 'ascii' | 'utf16le' | 'base64' | 'hex' | 'latin1' | 'binary';

/**
 * Encodes text to a buffer using the specified encoding
 * @param text The text to encode
 * @param encoding The encoding to use (defaults to utf-8)
 * @returns ArrayBuffer containing the encoded data
 */
export function encodeText(text: string, encoding: TextEncoding = 'utf-8'): ArrayBuffer {
  if (encoding === 'base64' || encoding === 'hex') {
    // First encode to the specified format, then create a buffer from that encoded string
    const encodedString = Buffer.from(text).toString(encoding);
    // Convert the encoded string back to a buffer and extract its ArrayBuffer
    const buffer = Buffer.from(encodedString);
    return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  }

  const buffer = iconv.encode(text, encoding);
  return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}

/**
 * Decodes a buffer to text using the specified encoding
 * @param buffer The buffer to decode
 * @param encoding The encoding to use (defaults to utf-8)
 * @returns The decoded text
 */
export function decodeText(buffer: ArrayBuffer, encoding: TextEncoding = 'utf-8'): string {
  const nodeBuffer = Buffer.from(buffer);

  if (encoding === 'base64' || encoding === 'hex') {
    return Buffer.from(nodeBuffer.toString(), encoding).toString();
  }

  return iconv.decode(nodeBuffer, encoding);
}
