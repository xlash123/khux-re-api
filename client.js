const https = require('https');
const { gunzipSync } = require('zlib');
const { Buffer } = require('buffer');
const { decryptJson, encryptUri, encryptJson } = require('./encoding');

const DEBUG = true;

var host = 'api-s.sp.kingdomhearts.com';
//var Host = '192.168.1.103';
var port = '443';
//var HostPort = '442';

const systemStatusData = '{"appSignature":"f048533ed4e1409a732831957a34a09f"}';
const uuid = '950f4192-f28a-469b-b602-dac828f0548a';

// Parses 'cookie_user_session_code' from cookies array
function getUserSessionCode(cookies) {
    if (Array.isArray(cookies)) {
        return cookies.find(c => c.startsWith('cookie_user_session_code=')).split(';')[0].substring('cookie_user_session_code='.length);
    }

    return '';
}

// Gets the cookie called 'nAJW839RbEHrfm6M'
function getWeirdCookie(cookies) {
    if (Array.isArray(cookies)) {
        return cookies.find(c => c.startsWith('nAJW839RbEHrfm6M=')).split(';')[0].substring('nAJW839RbEHrfm6M='.length);
    }

    return [];
}

function getNodeCookies(cookies) {
    if (Array.isArray(cookies)) {
        return cookies.filter(c => c.startsWith('nodeNo')).map(c => c.split(';')[0]);
    }

    return [];
}

class KHUXClient {
    sharedSecurityKey;
    nativeSessionId;
    cookieUserSessionCode;
    weirdNameCookie;
    nodeCookies;

    userData;

    isLoggedIn = false;

    constructor() {
    }
    
    packCookies() {
        return [
            'nAJW839RbEHrfm6M=' + this.weirdNameCookie,
            'cookie_user_session_code=' + this.cookieUserSessionCode,
        ].concat(this.nodeCookies);
    }

    // Returns that payload that the client always seems to send
    getSelfStatus() {
        return {
            ruv: Math.floor(Math.random() * 10000000000),
            deviceType: 2,
            systemVersion: '30',
            appVersion: '4.3.1'
        }
    }

    encryptUri(obj) {
        return encryptUri(obj, this.sharedSecurityKey);
    }

    encryptJson(obj) {
        return encryptJson(obj, this.sharedSecurityKey);
    }

    async performRequest(params, postData) {
        return new Promise((resolve, reject) => {
            const req = https.request(params, (res) => {
                const isGzip = res.headers['content-encoding'] === 'gzip';
                const isEncJson = res.headers['content-type'].includes('application/encoded-json');
                const isText = res.headers['content-type'].includes('text/html');
                let body;
        
                let cookies = [];
                if (res.headers) {
                    cookies = res.headers['set-cookie'] || [];
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
                    }
                    if (isText) {
                        body = body.toString();
                    } else if (isEncJson) {
                        body = decryptJson(body, this.sharedSecurityKey);
                    }
                    try {
                        body = JSON.parse(body.toString());
                    } catch (e) {
                        // Not a JSON element
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
    async login() {
        const systemRes = await this.performRequest({
            host,
            port,
            method: 'PUT',
            path: '/system/status',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF8',
                'Content-Length': systemStatusData.length
            },
        }, systemStatusData);

        const loginTokenRes = await this.performRequest({
            host,
            port,
            method: 'GET',
            path: '/login/token?m=0',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF8',
                'Cookie': [...systemRes.cookies].splice(1, 1),
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
        const sessionRes = await this.performRequest({
            host: urlSplit[2],
            port,
            method: 'POST',
            path: subdomain + '?m=0',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': sessionData.length,
            },
        }, sessionData);

        this.sharedSecurityKey = sessionRes.body.sharedSecurityKey;
        this.nativeSessionId = sessionRes.body.nativeSessionId;

        const loginData = this.encryptUri({
            ...this.getSelfStatus(),
            length: 19904060,
            digest: '3a4fee0d5cb05dd416b4bbc8cd4c8d57',
        });

        const loginRes = await this.performRequest({
            host,
            port,
            method: 'POST',
            path: '/system/login?m=0',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF8',
                'Content-Length': loginData.length,
                'Cookie': loginTokenRes.cookies,
                'x-sqex-hole-nsid': this.nativeSessionId,
                'X-Sqex-Hole-Retry': 0
            }
        }, loginData);

        this.cookieUserSessionCode = getUserSessionCode(loginRes.cookies);

        const coppaData = this.encryptUri(this.getSelfStatus());

        const coppaRes = await this.performRequest({
            host,
            port,
            method: 'GET',
            path: '/system/coppa?m=0&' + coppaData,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF8',
                'Cookie': loginRes.cookies,
                'x-sqex-hole-nsid': this.nativeSessionId,
                'X-Sqex-Hole-Retry': 0
            }
        });

        const khuxloginData = this.encryptUri(this.getSelfStatus());

        const khuxLoginCookies = [...coppaRes.cookies, 'cookie_user_session_code=' + this.cookieUserSessionCode]

        const khuxLoginRes = await this.performRequest({
            host,
            port,
            method: 'POST',
            path: '/khux/login?m=1',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF8',
                'Cookie': khuxLoginCookies,
                'x-sqex-hole-nsid': this.nativeSessionId,
                'X-Sqex-Hole-Retry': 0,
                'Content-Length': khuxloginData.length
            },
        }, khuxloginData);

        this.cookieUserSessionCode = getUserSessionCode(khuxLoginRes.cookies);
        this.weirdNameCookie = getWeirdCookie(khuxLoginRes.cookies);
        this.nodeCookies = getNodeCookies(khuxLoginRes.cookies);

        await this.initialStatus();

        this.isLoggedIn = true;

        return khuxLoginRes;
    }

    async initialStatus() {
        const tutorialStatusRes = await this.performRequest({
            host,
            port,
            method: 'GET',
            path: '/tutorial/status?m=1&' + this.encryptUri(this.getSelfStatus()),
            headers: {
                accept: '*/*',
                'accept-encoding': 'deflate, gzip',
                cookie: this.packCookies(),
                'x-sqex-hole-nsid': this.nativeSessionId,
                'x-sqex-hole-retry': '0',
            },
        });

        const userAwakenBody = this.encryptJson(this.getSelfStatus());
        const userAwakenRes = await this.performRequest({
            host,
            port,
            method: 'PUT',
            path: '/user/awakening?m=1',
            headers: {
                accept: '*/*',
                'accept-encoding': 'deflate, gzip',
                cookie: this.packCookies(),
                'x-sqex-hole-nsid': this.nativeSessionId,
                'x-sqex-hole-retry': '0',
                'content-length': userAwakenBody.length,
                'content-type': 'application/x-www-form-urlencoded'
            },
        }, userAwakenBody);

        const userRes = await this.performRequest({
            host,
            port,
            method: 'GET',
            path: '/user?m=1&' + this.encryptUri(this.getSelfStatus()),
            headers: {
                accept: '*/*',
                'accept-encoding': 'deflate, gzip',
                cookie: this.packCookies(),
                'x-sqex-hole-nsid': this.nativeSessionId,
                'x-sqex-hole-retry': '0',
            },
        });

        this.userData = userRes.body.userData;

        const userStartRes = await this.performRequest({
            host,
            port,
            method: 'GET',
            path: `/user/start?m=1&i=${this.userData.user.userId}&${this.encryptUri(this.getSelfStatus())}`,
            headers: {
                accept: '*/*',
                'accept-encoding': 'deflate, gzip',
                cookie: this.packCookies(),
                'x-sqex-hole-nsid': this.nativeSessionId,
                'x-sqex-hole-retry': '0',
            },
        });                
    }

    async getPetRecover() {
        return this.performRequest({
            host,
            port,
            method: 'GET',
            path: `pet/expedition/recover?m=1&i=${this.userData.user.userId}&${this.encryptUri(this.getSelfStatus())}`,
            headers: {
                accept: '*/*',
                'accept-encoding': 'deflate, gzip',
                cookie: this.packCookies(),
                'x-sqex-hole-nsid': this.nativeSessionId,
                'x-sqex-hole-retry': '0',
            },
        });
    }

    async getSystemMaster() {
        const resourceSizeBody = this.encryptJson({
            ...this.getSelfStatus(),
            resoMode: 0,
            masterRevision: 0,
            resourceRevision: 0,
            commonMasterRevision: 0,
            evResourceIds: [],
        });
        const resourceSizeRes = this.performRequest({
            host,
            port,
            method: 'PUT',
            path: `/system/resourcesize/20200423?m=1&i=${this.userData.user.userId}`,
            headers: {
                accept: '*/*',
                'accept-encoding': 'deflate, gzip',
                cookie: this.packCookies(),
                'x-sqex-hole-nsid': this.nativeSessionId,
                'x-sqex-hole-retry': '0',
                'content-length': resourceSizeBody.length,
                'content-type': 'application/x-www-form-urlencoded'
            },
        }, resourceSizeBody);

        const mastersBody = this.encryptUri({
            ...this.getSelfStatus(),
            revision: 0,
            commonRevision: 0,
        });

       return this.performRequest({
           host,
           port,
           method: 'GET',
           path: `/system/master/20200423?m=1&i=${this.userData.user.userId}&${mastersBody}`,
           headers: {
               accept: '*/*',
               'accept-encoding': 'deflate, gzip',
               cookie: this.packCookies(),
               'x-sqex-hole-nsid': this.nativeSessionId,
               'x-sqex-hole-retry': '0',
           },
       });
    }
    
    async getChatData() {
        return this.performRequest({
            host,
            port,
            method: 'GET',
            path: `/user/chat?m=1&i=${this.userData.user.userId}&${this.encryptUri(this.getSelfStatus())}`,
            headers: {
                accept: '*/*',
                'accept-encoding': 'deflate, gzip',
                cookie: this.packCookies(),
                'x-sqex-hole-nsid': this.nativeSessionId,
                'x-sqex-hole-retry': '0',
            },
        });
    }
    
    async getParty() {
        return this.performRequest({
            host,
            port,
            method: 'GET',
            path: `/user/chat?m=1&i=${this.userData.user.userId}&${this.encryptUri(this.getSelfStatus())}`,
            headers: {
                accept: '*/*',
                'accept-encoding': 'deflate, gzip',
                cookie: this.packCookies(),
                'x-sqex-hole-nsid': this.nativeSessionId,
                'x-sqex-hole-retry': '0',
            },
        });
    }

    async getJewels() {
        return this.performRequest({
            host,
            port,
            method: 'GET',
            path: `/user/stone?m=1&i=${this.userData.user.userId}&${this.encryptUri(this.getSelfStatus())}`,
            headers: {
                accept: '*/*',
                'accept-encoding': 'deflate, gzip',
                cookie: this.packCookies(),
                'x-sqex-hole-nsid': this.nativeSessionId,
                'x-sqex-hole-retry': '0',
            },
        });
    }

    async getUserData() {
        return this.performRequest({
            host,
            port,
            method: 'GET',
            path: '/user?m=1&' + this.encryptUri(this.getSelfStatus()),
            headers: {
                accept: '*/*',
                'accept-encoding': 'deflate, gzip',
                cookie: this.packCookies(),
                'x-sqex-hole-nsid': this.nativeSessionId,
                'x-sqex-hole-retry': '0',
            },
        }).body;
    }
}

module.exports = {
    KHUXClient,
};