const https = require('https');
const fs = require('fs');
const aes = require('aes-js');
const { b64 } = require('js-base64');
const { gunzipSync, gzipSync } = require('zlib');

// Some certificate stuff. Might not be necessary, but it doesn't hurt
https.globalAgent.options.ca = require('ssl-root-cas/latest').create();

const port = 443;

let responseCounter = 0;

// This is the AES-256 key that encrypts the JSON
// It is fetched during a session grab
let sharedSecurityKey;

// Use this function to make modifications to a body JSON object
function doBodyMod(body) {
	// Sample moficiation
	// if (body.tickerText) {
	// 	body.tickerText = 'This is a ticker injection';
	// }
}

// Takes a body and rezips/reencodes it if necessary
// Supports JSON and other types
function repackageBody(body, isGzip, isEncJson) {
	if (isEncJson) {
		const encJson = encryptJson(body, sharedSecurityKey);
		return gzipSync(encJson);
	} else if (isGzip) {
		return gzipSync(JSON.stringify(body));
	}
}

// SSL specifications for HTTPS
const ssl = {
	key: fs.readFileSync('key.pem', 'utf8'),
    cert: fs.readFileSync('cert.pem', 'utf8')
}

// Returns a decrypted JSON object
function decryptJson(encodedB64, secretKey) {
	const keyBytes = Buffer.from(secretKey);
	const aesCbc = new aes.ModeOfOperation.cbc(keyBytes);
	const decodedBuffer = Buffer.from(Base64.atob(encodedB64), 'binary');
	const decryptedBytes = aesCbc.decrypt(decodedBuffer);
	const retStr = aes.utils.utf8.fromBytes(decryptedBytes);
	return retStr.substring(0, retStr.lastIndexOf('}') + 1);
}

// Returns an encrypted version of this object
function encryptJson(obj, secretKey) {
	let jsonStr = JSON.stringify(obj);
	const modLen = jsonStr.length % 16;
	// Pad out string to multiple of 16 in order to encode
	if (modLen > 0) {
		console.log(modLen);
		jsonStr += '\0'.repeat(16 - modLen);
	}
	// Encrypt
	const keyBytes = Buffer.from(secretKey);
	const aesCbc = new aes.ModeOfOperation.cbc(keyBytes);
	const encJson = aesCbc.encrypt(aes.utils.utf8.toBytes(jsonStr));
	// Convert to b64
	return Base64.fromUint8Array(encJson);
}

// The main proxy server
const server = https.createServer(ssl, (req, res) => {
	// Options to route the initial request to the actual KH server
	const proxyOpts = {
		host: req.headers.host,
		port: 443,
		path: req.url,
		method: req.method
	};
	// Create proxy request to kh.com
	const pReq = https.request(proxyOpts, (pRes) => {
		// Once the kh.com request has come back...
		res.statusCode = pRes.statusCode;
		Object.keys(pRes.headers).forEach((h) => {
			res.setHeader(h, pRes.headers[h]);
		});
		// Is the incoming body in gzip encoding?
		const isGzip = res.getHeader('content-encoding') === 'gzip';
		// Is the incoming body encrypted JSON?
		const isEncJson = res.getHeader('content-type').includes('application/encoded-json');

		// The body of the response. To be filled
		let body;
		pRes.on('data', (chunk) => {
			if (body === undefined) {
				body = Buffer.from(chunk);
			} else {
				body = Buffer.concat([body, chunk]);
			}
		});
		pRes.on('end', () => {
			if (isGzip) {
				body = gunzipSync(body).toString();
				if (isEncJson) {
					body = decryptJson(body, sharedSecurityKey);
				}
			}

			// Attempt to parse the JSON
			try {
				body = JSON.parse(body.toString());
			} catch (e) {}

			if (typeof body === 'object') {
				// Log the AES key when we get it
				if (body.sharedSecurityKey) {
					sharedSecurityKey = body.sharedSecurityKey;
				}

				// This will allow custom manipulation of the body
				doBodyMod(body);
			}

			if (typeof body === 'object') {
				res.write(repackageBody(body, isGzip, isEncJson));
			} else {
				res.write(gzipSync(body));
			}

			log(false, {
				status: res.statusCode,
				headers: res.getHeaders(),
				body: body
			});
			// Finish proxy route
			res.end();
		})
	});
	let body = '';
	Object.keys(req.headers).forEach((h) => {
		pReq.setHeader(h, req.headers[h]);
	});
	req.on('data', (chunk) => {
		body += chunk.toString();
		pReq.write(chunk);
	});
	req.on('end', () => {
		try {
			body = JSON.parse(body);
		} catch (e) {}
		log(true, {
			url: req.headers.host + req.url,
			method: req.method,
			headers: req.headers,
			body: body
		});
		// Send out the proxied request
		pReq.end();
	})
});

// Log object
function log(isToSE, obj) {
	console.log('=======');
	if (isToSE) {
		console.log('To SE');
	} else {
		console.log('From SE');
	}
	console.dir(obj, { depth: null });
	console.log('=======');
}

server.listen(port);

console.log('starting on ' + port);