const crypto = require('crypto');
const libsodium = require('sodium-native');

/* Tries do demo decrpytion of UDP event sample data in Doorbird LAN API 0.36
 (https://www.doorbird.com/downloads/api_lan.pdf?rev=0.36) but fails.
 Approach 1 worked on November 1st 2023, and LAN API v0.34 */

var cypher = Buffer.from([0xDE, 0xAD, 0xBE, 0x02, 0x96, 0x13, 0x80, 0xD4, 0x62, 0x2E, 0xBE, 0xE7, 0x2A, 0x9F, 0xC3, 0xFF, 0x0B, 0xEF, 0x62, 0x64, 0xF2, 0xAE, 0x91, 0x94, 0x92, 0x14, 0x8B, 0xBD, 0x30, 0xEB, 0x05, 0xBD, 0xCE, 0x36, 0x7C, 0x33, 0xD4, 0x29, 0x3F, 0xAF, 0xE0, 0x60, 0x45, 0x9E, 0x65, 0x10]);
var decryptionKey = "BHYGHyRKtGzBjku2t2jX2UKidXYQ3VqmfbKoCtxXJ6O4lgSzpgIwZ6onrSh";


var keyBuffer = Buffer.from(decryptionKey.slice(0, 32), "utf8"); // Only use 32 Byte of the key
var nonce = cypher.subarray(4, 12);

var cipherText = Buffer.from(cypher.subarray(12, cypher.length));

var authTag = Buffer.alloc(16); // Not actually used



/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
/* Decrypt approach 1 - Will crash at line 28 for unknown reason */
/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

// Create decipher. Note: Using without authTagLength with chacha20-poly1305 was not possible for me
//

let decipher = crypto.createDecipheriv('chacha20-poly1305', keyBuffer, nonce, { authTagLength: authTag.length });


// Decrypt
let decryptedData = decipher.update(cipherText);

//decipher.setAuthTag(authTag); // Cipher is not encrypted with authTag! If this is set, decipher.final() will fail

// Validate the MAC is ok => this will throw an exception if the cipher, assoc data, or auth tag are inaccurate
let decryptedMessage = Buffer.concat([decryptedData, decipher.final()]);
console.log(decryptedMessage.toString('ascii'));


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
/* Decrypt approach 2 - Will crash at line 53 for unknown reason */
/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

let nonceBuffer1 = Buffer.alloc(libsodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
nonce.copy(nonceBuffer1);

let keyBuffer1 = Buffer.alloc(libsodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
keyBuffer.copy(keyBuffer1);

const decryptedMessage1 = Buffer.alloc(cipherText.length - libsodium.crypto_aead_xchacha20poly1305_ietf_ABYTES);

let res = libsodium.crypto_aead_xchacha20poly1305_ietf_decrypt(decryptedMessage1, null, cipherText, null, nonceBuffer1, keyBuffer1);
if (res == true)
{
    console.log(decryptedMessage1.toString('ascii'));
}
