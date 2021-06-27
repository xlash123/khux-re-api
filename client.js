const https = require('https');
const { gunzipSync } = require('zlib');
const { Buffer } = require('buffer');
const { decryptJson, encryptUri, encryptJson, decryptRaw } = require('./encoding');

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

        return cookies.find(c => c.startsWith('cookie_user_session_code='))?.split(';')[0]?.substring('cookie_user_session_code='.length);
    }

    return false;
}

// Gets the cookie called 'nAJW839RbEHrfm6M'
function getWeirdCookie(cookies) {
    if (Array.isArray(cookies)) {
        return cookies.find(c => c.startsWith('nAJW839RbEHrfm6M='))?.split(';')[0]?.substring('nAJW839RbEHrfm6M='.length);
    }

    return false;
}

function getNodeCookies(cookies) {
    if (Array.isArray(cookies)) {
        return cookies.filter(c => c.startsWith('nodeNo')).map(c => c.split(';')[0]);
    }

    return false;
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

    // Parse through cookies and update them locally
    setCommonCookies(cookies) {
        const newUserSession = getUserSessionCode(cookies);
        if (newUserSession) {
            this.cookieUserSessionCode = newUserSession;
        }

        const newWeirdCookie = getWeirdCookie(cookies);
        if (newWeirdCookie) {
            this.weirdNameCookie = newWeirdCookie;
        }

        const newNodes = getNodeCookies(cookies);
        if (newNodes) {
            this.nodeCookies = newNodes;
        }
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

    encryptUri(obj, pad = '\x04') {
        return encryptUri(obj, this.sharedSecurityKey, pad);
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
                    this.setCommonCookies(cookies);
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
    async login(initUser = true) {
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

        if (initUser) {
            await this.initialStatus();
        }

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

    async startStage() {
        const stageBody = this.encryptUri({
            stageId: 1001010,
            supportUserId: 0,
            userKeybladeId: 1789171,
            isSteal: 1,
            ...this.getSelfStatus(),
        }, '\x0B');
        return this.performRequest({
            host,
            port,
            method: 'POST',
            path: `/stage/start?m=1&i=${this.userData.user.userId}`,
            headers: {
                host: 'api-s.sp.kingdomhearts.com',
                accept: '*/*',
                'accept-encoding': 'deflate, gzip',
                cookie: this.packCookies(),
                'x-sqex-hole-nsid': this.nativeSessionId,
                'x-sqex-hole-retry': '0',
                'content-length': stageBody.length,
                'content-type': 'application/x-www-form-urlencoded'
            },
        }, stageBody);
    }

    async clearStage() {
        const stageBody = this.encryptUri({
            getPoint: { exp: 29, raidPoint: 0, money: 3654, lux: 16220, score: 0 },
            getMaterials: [],
            getEnemyDropItems: [
                8, 9, 10, 5,
                6, 2,  3
            ],
            getTreasures: [ 13, 14 ],
            clearMissionIds: [ 1, 2, 3 ],
            enemyDeadNumber: 7,
            mimicDeadNumber: 0,
            rareEnemyDeadNumber: 0,
            maximumDamage: 1253181,
            guiltBurstMaximumDamage: 0,
            burst: 210000,
            conditions: {
                '04_0': 0,
                '04_1': 0,
                '04_2': 0,
                '05_0': 3,
                '07_0': 3,
                '08_0': 3,
                '09_0': 0,
                '10_0': 0,
                '11_0': 0,
                '11_1': 0,
                '11_2': 0,
                '11_3': 0,
                '12_0': 1,
                '12_1': 0,
                '12_2': 0,
                '14_0': 0,
                '14_1': 0,
                '14_2': 0,
                '15_0': 0,
                '15_1': 0,
                '15_2': 0,
                '17_0': 2,
                '18_0': 0,
                '19_0': 0,
                '19_1': 0,
                '19_2': 0,
                '28_0': 1,
                '32_0': 3,
                '36_0': 0,
                '37_0': 2414
            },
            missionConditions: { defeated: { '5': 2, '11': 1, '141': 3, '10011': 1 } },
            ...this.getSelfStatus(),
        }, '\x02');
    }

    async quitStage() {
        const stageBody = this.encryptUri(this.getSelfStatus(), '\x06');
        return this.performRequest({
            host,
            port,
            method: 'POST',
            path: `/stage/retire?m=1&i=${this.userData.user.userId}`,
            headers: {
                host: 'api-s.sp.kingdomhearts.com',
                accept: '*/*',
                'accept-encoding': 'deflate, gzip',
                cookie: this.packCookies(),
                'x-sqex-hole-nsid': this.nativeSessionId,
                'x-sqex-hole-retry': '0',
                'content-length': stageBody.length,
                'content-type': 'application/x-www-form-urlencoded'
            },
        }, stageBody);
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
        // const tutorialStatusRes = await this.performRequest({
        //     host,
        //     port,
        //     method: 'GET',
        //     path: '/tutorial/status?m=1&' + this.encryptUri(this.getSelfStatus()),
        //     headers: {
        //         accept: '*/*',
        //         'accept-encoding': 'deflate, gzip',
        //         cookie: this.packCookies(),
        //         'x-sqex-hole-nsid': this.nativeSessionId,
        //         'x-sqex-hole-retry': '0',
        //     },
        // });

        // const resourceSizeBody1 = this.encryptUri({
        //     resoMode: 0,
        //     masterRevision: 0,
        //     resourceRevision: 0,
        //     commonMasterRevision: 0,
        //     evResourceIds: [],
        //     ...this.getSelfStatus(),
        // });
        // const resourceSizeRes1 = await this.performRequest({
        //     host,
        //     port,
        //     method: 'PUT',
        //     path: `/system/resourcesize/20200423?m=1`,
        //     headers: {
        //         host: 'api-s.sp.kingdomhearts.com',
        //         accept: '*/*',
        //         'accept-encoding': 'deflate, gzip',
        //         cookie: this.packCookies(),
        //         'x-sqex-hole-nsid': this.nativeSessionId,
        //         'x-sqex-hole-retry': '0',
        //         'content-length': resourceSizeBody1.length,
        //         'content-type': 'application/x-www-form-urlencoded'
        //     },
        // }, resourceSizeBody1);

        // const resourceSizeBody2 = this.encryptUri({
        //     resoMode: 1,
        //     masterRevision: 0,
        //     resourceRevision: 0,
        //     commonMasterRevision: 0,
        //     evResourceIds: [],
        //     ...this.getSelfStatus(),
        // });
        // const resourceSizeRes2 = await this.performRequest({
        //     host,
        //     port,
        //     method: 'PUT',
        //     path: `/system/resourcesize/20200423?m=1`,
        //     headers: {
        //         host: 'api-s.sp.kingdomhearts.com',
        //         accept: '*/*',
        //         'accept-encoding': 'deflate, gzip',
        //         cookie: this.packCookies(),
        //         'x-sqex-hole-nsid': this.nativeSessionId,
        //         'x-sqex-hole-retry': '0',
        //         'content-length': resourceSizeBody2.length,
        //         'content-type': 'application/x-www-form-urlencoded'
        //     },
        // }, resourceSizeBody2);

        const mastersBody = this.encryptUri({
            revision: 0,
            commonRevision: 0,
            ...this.getSelfStatus(),
        }, '\x05'); // This padding character is extremely necessary
        return this.performRequest({
            host,
            port,
            method: 'GET',
            path: `/system/master/20200423?m=1&${mastersBody}`,
            headers: {
                host: 'api-s.sp.kingdomhearts.com',
                accept: '*/*',
                'accept-encoding': 'deflate, gzip',
                cookie: this.packCookies(),
                'x-sqex-hole-nsid': this.nativeSessionId,
                'x-sqex-hole-retry': '0',
            },
        }, '');
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

    async saveAllUserData() {
        
    }
}

module.exports = {
    KHUXClient,
};