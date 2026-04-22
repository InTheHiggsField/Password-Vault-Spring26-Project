/**
 * Cryptographic utilities for Password Vault
 * Handles PBKDF2 key derivation and encoding/decoding
 */

/**
 * Convert an ArrayBuffer to a hex string
 */
export function bufferToHex(buffer: ArrayBuffer): string {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

/**
 * Convert a hex string to a Uint8Array
 */
export function hexToBuffer(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) {
        throw new Error("Invalid hex string: odd length");
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

/**
 * Generate a cryptographically random 16-byte salt
 */
export function generateRandomSalt(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(16));
}

/**
 * Derive master keys (authKey + encryptionKey) from password and salt using PBKDF2.
 *
 * Security notes:
 * - authKey:       Sent to backend — backend hashes with bcrypt before storing
 * - encryptionKey: Never leaves the browser — used to AES-GCM encrypt vault entries
 * - iterations:    100,000 — consistent for all users. Do not change without a
 *                  migration plan; changing this invalidates all existing authKey hashes.
 */
export async function deriveMasterKeys(
    password: string,
    salt: Uint8Array,
    iterations: number = 600000
): Promise<{ authKey: ArrayBuffer; encryptionKey: ArrayBuffer }> {
    const rawKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: salt.buffer as ArrayBuffer,
            iterations: iterations,
            hash: "SHA-256",
        },
        rawKey,
        512
    );

    return {
        authKey: bits.slice(0, 32),    // first 32 bytes → sent to backend
        encryptionKey: bits.slice(32), // last 32 bytes  → stays in browser
    };
}

/**
 * Derive only the encryptionKey from password and salt.
 * Used during the backfill re-encryption path on first login after the
 * salt migration, where we need the old email-based key to decrypt
 * existing vault entries before re-encrypting with the new random-salt key.
 */
export async function deriveEncryptionKeyOnly(
    password: string,
    salt: Uint8Array,
    iterations: number = 100000
): Promise<ArrayBuffer> {
    const { encryptionKey } = await deriveMasterKeys(password, salt, iterations);
    return encryptionKey;
}
