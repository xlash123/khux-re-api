const https = require('https');
const fs = require('fs');
const { gunzipSync } = require('zlib');

https.globalAgent.options.ca = require('ssl-root-cas/latest').create();

const port = 443;

let responseCounter = 0;

const ssl = {
	key: fs.readFileSync('key.pem', 'utf8'),
    cert: fs.readFileSync('cert.pem', 'utf8')
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
				if (isEncJson) {
					fs.writeFileSync(`packets/${responseCounter++}.gz`, body, 'binary');
					console.log('wrote as' + (responseCounter - 1));
				}
				body = gunzipSync(body).toString().trim();
			}
			try {
				body = JSON.parse(body.toString());
			} catch (e) {}

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