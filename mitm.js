const https = require('https');
const fs = require('fs');
const process = require('process');
const { Buffer } = require('buffer');
const { gunzipSync, gzipSync } = require('zlib');
const readline = require('readline');

const {
	decryptJson,
	decryptUri,
	encryptJson,
} = require('./encoding');

const port = 443;

let responseCounter = 0;

// Allows the server messages to be written directly to the client without storing in RAM first
//   This disables any form of modifications that could be made,
// but it will also write all the bodies to disk exactly how it is received
let seamlessLog = false;

// This is the AES-256 key that encrypts the JSON
// It is fetched during a session grab
let sharedSecurityKey;

// Use this function to make modifications to a body JSON object
function doBodyMod(body) {
	// Sample moficiations
	// if (body.tickerText) {
	// 	body.tickerText = 'This is a ticker injection';
	// }
	// if (body.popUpViewUrl) {
	// 	body.popUpViewUrl = ['https://www.youtube.com/watch?v=dQw4w9WgXcQ', 'https://knowyourmeme.com/memes/buff-riku'];
	// }
}

// Modifies the JSON payload that goes to the server
// VERY DANGEROUS! If used improperly, you could probably get a ban
// function doClientBodyMod(body) {

// }

// Takes a body and rezips/reencodes it if necessary
// Supports JSON and other types
function repackageBody(body, isGzip, isEncJson) {
	if (isEncJson) {
		const encJson = encryptJson(body, sharedSecurityKey);
		return gzipSync(encJson);
	} else if (isGzip) {
		return gzipSync(JSON.stringify(body));
	}
	return body;
}

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

// SSL specifications for HTTPS
const ssl = {
	key: fs.readFileSync('key.pem', 'utf8'),
    cert: fs.readFileSync('cert.pem', 'utf8')
}

function launchMitm() {
    https.globalAgent.options.ca = require('ssl-root-cas').create();
    // The main proxy server
    const server = https.createServer(ssl, (req, res) => {
        console.log('Connection');
        // Options to route the initial request to the actual KH server
        const proxyOpts = {
            host: req.headers.host,
            port: 443,
            path: req.url,
            method: req.method,
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

            // If activated, the log file to write to
            let logFile;
            if (seamlessLog) {
                logFile = fs.openSync(`packets/${responseCounter++}.bin`, 'w');
            }
            pRes.on('data', (chunk) => {
                if (seamlessLog) {
                    res.write(chunk);
                    fs.writeSync(logFile, chunk);
                } else {
                    res.write(chunk);
                    if (body === undefined) {
                        body = Buffer.from(chunk);
                    } else {
                        body = Buffer.concat([body, chunk]);
                    }
                }
            });
            let modBody;
            pRes.on('end', () => {
                if (!seamlessLog) {
                    modBody = body;
                    if (isGzip) {
                        modBody = gunzipSync(modBody).toString();
                    }
                    if (isEncJson) {
                        modBody = decryptJson(modBody, sharedSecurityKey);
                    }

                    // Attempt to parse the JSON
                    try {
                        modBody = JSON.parse(modBody.toString());
                    } catch (e) {
                        console.log(e);
                    }

                    if (typeof modBody === 'object') {

                        // Log the AES key when we get it
                        if (modBody.sharedSecurityKey) {
                            sharedSecurityKey = modBody.sharedSecurityKey;
                        }

                        // This will allow custom manipulation of the body
                        doBodyMod(modBody);
                    }
                } else {
                    fs.closeSync(logFile);
                }

                log(false, {
                    status: res.statusCode,
                    headers: res.getHeaders(),
                    body: seamlessLog ? 'logged to disk' : modBody,
                });
                // Finish proxy route
                res.end();
            })
        });

        // The payload to send
        let body = '';
        Object.keys(req.headers).forEach((h) => {
            pReq.setHeader(h, req.headers[h]);
        });
        req.on('data', (chunk) => {
            body += chunk.toString();
            pReq.write(body);
        });
        req.on('end', () => {
            // The payload to send that exists in the url
            let vBody;
            if (req.method === 'GET' && sharedSecurityKey) {
                vBody = decryptUri(req.url, sharedSecurityKey);
            }
            if (sharedSecurityKey) {
                body = decryptUri(body, sharedSecurityKey);
            }

            // Attempt to JSON parse the body(ies)
            try {
                body = JSON.parse(body);
            } catch (e) {
                console.log(e);
            }
            try {
                vBody = JSON.parse(vBody);
            } catch (e) {
                console.log(e);
            }

            // This allows for modification of the payload send to the server
            // In some cases, it crashes, so this is still to be worked on

            // if (typeof body === 'object' && sharedSecurityKey) {
            // 	doClientBodyMod(body);
            // 	const newBody = encryptUri(body, sharedSecurityKey);
            // 	pReq.setHeader('content-length', newBody.length);
            // 	pReq.write(newBody);
            // } else if (typeof body === 'object') {
            // 	pReq.write(JSON.stringify(body));
            // } else {
            // 	pReq.write(body);
            // }

            log(true, {
                url: req.headers.host + req.url,
                method: req.method,
                headers: req.headers,
                body: body,
                vBody
            });
            // Send out the proxied request
            pReq.end();
        })
    });

    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
        terminal: false
    });
    
    rl.on('line', (line) => {
        if (line.startsWith('seamless')) {
            seamlessLog = !seamlessLog;
            console.log('Seamless mode is ' + (seamlessLog ? 'on' : 'off'));
        }
    });
    
    server.listen(port);
    
    console.log('starting on ' + port);

    return server;
}

module.exports = {
    launchMitm,
};
