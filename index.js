const https = require('https');
const fs = require('fs');
const aes = require('aes-js');
const { b64 } = require('js-base64');
const { gunzipSync } = require('zlib');

https.globalAgent.options.ca = require('ssl-root-cas/latest').create();

const port = 443;

let responseCounter = 0;

// This is the AES-256 key that encrypts the JSON
// It is fetched during a session grab
let sharedSecurityKey;

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
	return aes.utils.utf8.fromBytes(decryptedBytes).trim();
}

const server = https.createServer(ssl, (req, res) => {
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
		const isGzip = res.getHeader('content-encoding') === 'gzip';
		const isEncJson = res.getHeader('content-type').includes('application/encoded-json');
		let body;
		let fillStart;
		pRes.on('data', (chunk) => {
			if (body === undefined) {
				body = Buffer.from(chunk);
			} else {
				body = Buffer.concat([body, chunk]);
			}
			fillStart += chunk.length;
			res.write(chunk);
		});
		pRes.on('end', () => {
			if (isGzip) {
				body = gunzipSync(body).toString();
				if (isEncJson) {

					body = decryptJson(body, sharedSecurityKey);
				}
			}
			try {
				body = JSON.parse(body.toString());
			} catch (e) {}

			// Log the AES key when we get it
			if (typeof body === 'object') {
				if (body.sharedSecurityKey) {
					sharedSecurityKey = body.sharedSecurityKey;
				}
			}

			console.log('From SE', {
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
		console.log('To SE', {
			url: req.headers.host + req.url,
			method: req.method,
			headers: req.headers,
			body: body
		});
		// Send out the proxied request
		pReq.end();
	})
});

server.listen(port);

console.log('starting on ' + port);