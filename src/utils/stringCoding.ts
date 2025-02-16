import { createHash } from 'crypto';

export function deriveStringToBuffer(
    ss: string | undefined,
    targetLength: number
): Buffer {
    if (!ss) {
        return Buffer.alloc(targetLength);
    }

    let base64Buffer: Buffer | null = null;
    try {
        base64Buffer = Buffer.from(ss, 'base64');
    } catch { }

    if (base64Buffer?.length === targetLength) {
        return base64Buffer;
    }

    const inputBuffer = Buffer.from(ss, 'utf8');
    const hash = createHash('sha256').update(inputBuffer).digest();

    const outputBuffer = Buffer.alloc(targetLength);
    hash.copy(outputBuffer, 0, 0, targetLength);

    return outputBuffer;
}

export function deriveStringToUint8Array(
    ss: string | undefined,
    targetLength: number
): Uint8Array {
    return new Uint8Array(deriveStringToBuffer(ss, targetLength));
}
