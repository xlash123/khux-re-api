const aes = require('aes-js');
const Buffer = require('buffer');
const { Base64 } = require('js-base64');

// Returns a decrypted JSON object
function decryptJson(encodedB64, secretKey) {
	const keyBytes = Buffer.from(secretKey);
	const aesCbc = new aes.ModeOfOperation.cbc(keyBytes);
	const decodedBuffer = Buffer.from(Base64.atob(encodedB64), 'binary');
	const decryptedBytes = aesCbc.decrypt(decodedBuffer);
	const retStr = aes.utils.utf8.fromBytes(decryptedBytes);
	return retStr.substring(0, retStr.lastIndexOf('}') + 1);
}

// Decrypts a user-sent message
function decryptUri(encoded, secretKey) {
	const urlSearch = new URLSearchParams(encoded);
	const v = urlSearch.get('v');
	if (v)
		return decryptJson(v, secretKey);
	return encoded;
}

// Encrypts a JSON payload to go in the url
function encryptUri(obj, secretKey) {
	return 'v=' + encodeURIComponent(encryptJson(obj, secretKey, '\4'));
}

// Returns an encrypted version of this object
function encryptJson(obj, secretKey, padChar = '\0') {
	let jsonStr = aes.utils.utf8.toBytes(JSON.stringify(obj));
	const modLen = jsonStr.length % 16;
	// Pad out string to multiple of 16 in order to encode
	if (modLen > 0) {
		const padding = aes.utils.utf8.toBytes(padChar.repeat(16 - modLen));
		const newArr = new Uint8Array(jsonStr.length + padding.length);
		newArr.set(jsonStr);
		newArr.set(padding, jsonStr.length);
		jsonStr = newArr;
	}
	// Encrypt
	const keyBytes = Buffer.from(secretKey);
	const aesCbc = new aes.ModeOfOperation.cbc(keyBytes);
	const encJson = aesCbc.encrypt(jsonStr);
	// Convert to b64
	return Base64.fromUint8Array(encJson);
}

module.exports = {
    decryptJson,
    decryptUri,
    encryptUri,
    encryptJson,
};
