/**
 * Updated by Jomar Romero Balmores
 * September 2023
 * I optimize the code while maintaining compatibility, I make a few improvements. I utilize async/await more efficiently, reduce redundant code, and update the code readability.
 */



/*******************************************************************************
 * Global Variables
 ******************************************************************************/

const LATEST_API_VERSION = "0.0.1";

const apiVersions = {};

/*******************************************************************************
 * API Version 0.0.1 (Latest)
 ******************************************************************************/

apiVersions[LATEST_API_VERSION] = {
  // Static salt and initialization vector for shorter, less secure links
  salt: Uint8Array.from([236, 231, 167, 249, 207, 95, 201, 235, 164, 98, 246, 26, 176, 174, 72, 249]),
  iv: Uint8Array.from([255, 237, 148, 105, 6, 255, 123, 202, 115, 130, 16, 116]),

  // Generate random salt and initialization vectors
  randomSalt: async function () {
    return window.crypto.getRandomValues(new Uint8Array(16));
  },

  randomIv: async function () {
    return window.crypto.getRandomValues(new Uint8Array(12));
  },

  // Import the raw, plain-text password and derive a key using a SHA-256 hash
  // and PBKDF2. Use the static salt for this version if one has not been given
  deriveKey: async function (password, salt = null) {
    if (salt === null) {
      salt = this.salt;
    }
    const rawKey = await window.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits", "deriveKey"]
    );
    return await window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      rawKey,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  },

  // Encrypt the text using AES-GCM with a key derived from the password. Takes
  // in strings for text and password, as well as optional salt and iv. Uses the
  // static iv for this version if one is not given.
  encrypt: async function (text, password, salt = null, iv = null) {
    const key = await this.deriveKey(password, salt);
    iv = iv || this.iv;
    const encodedText = new TextEncoder().encode(text);
    return window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encodedText);
  },

  // Decrypt the text using AES-GCM with a key derived from the password. Takes
  // in text as an ArrayBuffer and a string password, as well as optional salt
  // and iv. Uses the static iv for this version if one is not given.
  decrypt: async function (text, password, salt = null, iv = null) {
    const key = await this.deriveKey(password, salt);
    iv = iv || this.iv;
    const decryptedBinary = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      text
    );
    return new TextDecoder().decode(decryptedBinary);
  },
};

