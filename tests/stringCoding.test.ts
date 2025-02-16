import { deriveStringToBuffer, deriveStringToUint8Array } from '../src/utils/stringCoding';

describe('stringCoding', () => {
  describe('deriveStringToBuffer', () => {
    it('should return empty buffer when input is undefined', () => {
      const result = deriveStringToBuffer(undefined, 32);
      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBe(32);
      expect(result).toEqual(Buffer.alloc(32));
    });

    it('should return empty buffer when input is empty string', () => {
      const result = deriveStringToBuffer('', 32);
      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBe(32);
      expect(result).toEqual(Buffer.alloc(32));
    });

    it('should return correct buffer for normal string', () => {
      const input = 'test string';
      const result = deriveStringToBuffer(input, 32);
      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBe(32);
    });

    it('should handle base64 encoded string', () => {
      const input = Buffer.from('test').toString('base64');
      const result = deriveStringToBuffer(input, 4);
      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBe(4);
      expect(result).toEqual(Buffer.from('test'));
    });

    it('should handle very long string', () => {
      const input = 'a'.repeat(100000);
      const result = deriveStringToBuffer(input, 32);
      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBe(32);
    });
  });

  describe('deriveStringToUint8Array', () => {
    it('should return correct Uint8Array', () => {
      const result = deriveStringToUint8Array('test', 32);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(32);
    });
  });
});
