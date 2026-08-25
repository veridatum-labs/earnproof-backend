import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

const ENCRYPTED_PREFIX = "enc:v1:";
const LEGACY_PREFIX = "redacted:";

export function encryptProtectedAmount(amount: string, keyMaterial: string) {
  const key = decodeAmountKey(keyMaterial);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(amount, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return `${ENCRYPTED_PREFIX}${iv.toString("base64url")}:${tag.toString(
    "base64url",
  )}:${ciphertext.toString("base64url")}`;
}

export function decryptProtectedAmount(value: string, keyMaterial: string) {
  if (value.startsWith(LEGACY_PREFIX)) {
    return Buffer.from(value.slice(LEGACY_PREFIX.length), "base64url").toString(
      "utf8",
    );
  }

  if (!value.startsWith(ENCRYPTED_PREFIX)) {
    throw new Error("Unsupported protected amount format");
  }

  const [ivValue, tagValue, ciphertextValue] = value
    .slice(ENCRYPTED_PREFIX.length)
    .split(":");

  if (!ivValue || !tagValue || !ciphertextValue) {
    throw new Error("Invalid protected amount payload");
  }

  const decipher = createDecipheriv(
    "aes-256-gcm",
    decodeAmountKey(keyMaterial),
    Buffer.from(ivValue, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(tagValue, "base64url"));

  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextValue, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

function decodeAmountKey(keyMaterial: string) {
  const key = /^[a-fA-F0-9]{64}$/.test(keyMaterial)
    ? Buffer.from(keyMaterial, "hex")
    : Buffer.from(keyMaterial, "base64");

  if (key.length !== 32) {
    throw new Error("PAYMENT_ENCRYPTION_KEY must decode to 32 bytes");
  }

  return key;
}
