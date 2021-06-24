const https = require('https');
const { gunzipSync } = require('zlib');
const { Buffer } = require('buffer');
const { decryptJson, encryptUri } = require('./encoding');

const DEBUG = true;

let sharedSecurityKey;
var host = 'api-s.sp.kingdomhearts.com';
//var Host = '192.168.1.103';
var port = '443';
//var HostPort = '442';

const systemStatusData = '{"appSignature":"f048533ed4e1409a732831957a34a09f"}';
const uuid = '950f4192-f28a-469b-b602-dac828f0548a';

async function performRequest(params, postData) {
    return new Promise((resolve, reject) => {
        const req = https.request(params, (res) => {
            const isGzip = res.headers['content-encoding'] === 'gzip';
            const isEncJson = res.headers['content-type'].includes('application/encoded-json');
            let body;
    
            let cookies = '';
            if (res.headers) {
                cookies = res.headers['set-cookie']?.toString() || '';
            }
    
            res.on('data', (chunk) => {
                if (body === undefined) {
                    body = Buffer.from(chunk);
                } else {
                    body = Buffer.concat([body, chunk]);
                }
            });
            res.on('end', () => {
                if (isGzip) {
                    body = gunzipSync(body).toString();
                    if (isEncJson) {
                        body = decryptJson(body, sharedSecurityKey);
                    }
                }
                try {
                    body = JSON.parse(body.toString());
                } catch (e) {
                    console.error(e);
                }
                const response = {
                    body,
                    headers: res.headers,
                    cookies,
                };
                if (DEBUG) {
                    console.dir({
                        params,
                        response,
                        payload: postData,
                    }, { depth: 10 });
                }
                resolve(response);
            });
        });
        req.on('error', function(err) {
            reject(err);
        });
        if (postData) {
            req.write(postData);
        }
        req.end();
    });
}

// Perform the first few requests that establish a login
async function login() {
    const systemRes = await performRequest({
        host,
        port,
        method: 'PUT',
        path: '/system/status',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF8',
            'Content-Length': systemStatusData.length
        },
    }, systemStatusData);

    const loginTokenRes = await performRequest({
        host,
        port,
        method: 'GET',
        path: '/login/token?m=0',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF8',
            'Cookie': systemRes.cookies,
        },
    })

    const urlSplit = loginTokenRes.body.url.split('/');
    let subdomain = '';
    for(var i = 3; i < urlSplit.length; i++) {
        subdomain += '/' + urlSplit[i];
    }
    const sessionData = JSON.stringify({
        UUID: uuid,
        deviceType: 2,
        nativeToken: loginTokenRes.body.nativeToken,
    });
    const sessionRes = await performRequest({
        host: urlSplit[2],
        port,
        method: 'POST',
        path: subdomain + '?m=0',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Content-Length': sessionData.length,
        },
    }, sessionData);

    sharedSecurityKey = sessionRes.body.sharedSecurityKey;

    const loginData = encryptUri({
        length: 19904060,
        digest: '3a4fee0d5cb05dd416b4bbc8cd4c8d57',
        ruv: Math.floor(Math.random() * 10000000000),
        deviceType: 2,
        systemVersion: "25",
        appVersion: "4.3.1"
    }, sharedSecurityKey, false);

    const loginRes = await performRequest({
        host,
        port,
        method: 'POST',
        path: '/system/login?m=0',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF8',
            'Content-Length': loginData.length,
            'Cookie': loginTokenRes.cookies,
            'N-Sqex-Hole-Nsid': sessionRes.body.nativeSessionId,
            'X-Sqex-Hole-Retry': 0
        }
    }, loginData)

    return loginRes;
}

module.exports = {
    login,
};
