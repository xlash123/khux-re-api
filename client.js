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

function getUsefulBody(response) {
    // if (!response || !response.body) return undefined;
    const { ret, ...newObj } = response.body;
    return newObj;
}

function cleanSaveObject(save) {
    const ret = {};
    Object.keys(save).forEach((key) => {
        console.log(key);
        ret[key] = getUsefulBody(save[key]);
    });
    return ret;
}

class KHUXClient {
    sharedSecurityKey = '';
    nativeSessionId = '';
    cookieUserSessionCode = '';
    weirdNameCookie = '';
    nodeCookies = [];
    uuid;
    deviceType;

    userData;
    darkUser;

    isLoggedInKhux = false;
    isLoggedInDr = false;

    isNewKhux = true;
    isNewDr = true;

    constructor(uuid, deviceType = 2) {
        this.uuid = uuid;
        this.deviceType = deviceType;
    }

    getSavedUserId() {
        return this.userData?.user?.userId;
    }

    getSavedDarkUserId() {
        return this.darkUser?.darkUser?.userId;
    }
    
    packCookies() {
        const ret = [];
        if (this.weirdNameCookie) {
            ret.push('nAJW839RbEHrfm6M=' + this.weirdNameCookie)
        }
        if (this.cookieUserSessionCode) {
            ret.push('cookie_user_session_code=' + this.cookieUserSessionCode);
        }
        return ret.concat(this.nodeCookies);
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
            deviceType: this.deviceType,
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

    async performRequest(paramsObj, postData, pad = '\x04') {
        // Allow for default parameters and headers
        const params = {
            host,
            port,
            method: 'GET',
            headers: {},
        };
        const headers = {
            accept: '*/*',
            'accept-encoding': 'deflate, gzip',
            cookie: this.packCookies(),
        };
        if (this.nativeSessionId) {
            headers['x-sqex-hole-nsid'] = this.nativeSessionId,
            headers['x-sqex-hole-retry'] = '0';
        }
        if (typeof paramsObj === 'object') {
            Object.assign(params, paramsObj);
        }
        if (params.method !== 'GET') {
            headers['content-type'] = 'application/x-www-form-urlencoded;charset=UTF8';
            headers['content-length'] = postData.length;
        }
        if (paramsObj?.headers) {
            Object.assign(headers, paramsObj.headers);
        }
        else if (typeof paramsObj === 'string') {
            const m = this.isLoggedInKhux ? 1 : (this.isLoggedInDr ? 2 : 0);
            const userId = this.isLoggedInKhux ? this.getSavedUserId() : (this.isLoggedInDr ? this.getSavedDarkUserId() : '');
            // Set path if paramsObj is a string and add normal flair
            params.path = `${paramsObj}?m=${m}&${userId ? `i=${userId}` : ''}&${this.encryptUri(this.getSelfStatus(), pad)}`;
        }
        Object.assign(params.headers, headers);

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
                    } else if (body?.ret?.error) {
                        console.log(body.ret.error);
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

    // Perform enough requests to obtain a key and session
    async init(mode = 0) {
        this.sharedSecurityKey = '';
        this.nativeSessionId = '';
        this.cookieUserSessionCode = '';
        this.weirdNameCookie = '';
        this.nodeCookies = [];

        this.userData = undefined;
        this.darkUser = undefined;

        this.isLoggedInKhux = false;
        this.isLoggedInDr = false;

        this.isNewKhux = true;
        this.isNewDr = true;
        

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
            path: `/login/token?m=${mode}`,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF8',
                'Cookie': [...systemRes.cookies].splice(1, 1),
            },
        });

        const urlSplit = loginTokenRes.body.url.split('/');
        let subdomain = '';
        for(var i = 3; i < urlSplit.length; i++) {
            subdomain += '/' + urlSplit[i];
        }
        const sessionData = JSON.stringify({
            UUID: this.uuid,
            deviceType: this.deviceType,
            nativeToken: loginTokenRes.body.nativeToken,
        });
        const sessionRes = await this.performRequest({
            host: urlSplit[2],
            port,
            method: 'POST',
            path: subdomain + `?m=${mode}`,
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
            path: `/system/login?m=${mode}`,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF8',
                'Content-Length': loginData.length,
                'Cookie': loginTokenRes.cookies,
                'x-sqex-hole-nsid': this.nativeSessionId,
                'X-Sqex-Hole-Retry': 0
            }
        }, loginData);
        this.isNewKhux = loginRes.body.systemLogin.newcomerKhux;
        this.isNewDr = loginRes.body.systemLogin.newcomerDark;

        this.cookieUserSessionCode = getUserSessionCode(loginRes.cookies);

        const coppaData = this.encryptUri(this.getSelfStatus());

        const coppaRes = await this.performRequest({
            host,
            port,
            method: 'GET',
            path: `/system/coppa?m=${mode}&${coppaData}`,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF8',
                'Cookie': loginRes.cookies,
                'x-sqex-hole-nsid': this.nativeSessionId,
                'X-Sqex-Hole-Retry': 0
            }
        });
    }

    async loginKhux(initUser = true) {
        const khuxloginData = this.encryptUri(this.getSelfStatus());
        const khuxLoginRes = await this.performRequest({
            host,
            port,
            method: 'POST',
            path: '/khux/login?m=1',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded;charset=UTF8',
                'Cookie': this.packCookies(),
                'x-sqex-hole-nsid': this.nativeSessionId,
                'X-Sqex-Hole-Retry': 0,
                'Content-Length': khuxloginData.length
            },
        }, khuxloginData);

        this.cookieUserSessionCode = getUserSessionCode(khuxLoginRes.cookies);
        this.weirdNameCookie = getWeirdCookie(khuxLoginRes.cookies);
        this.nodeCookies = getNodeCookies(khuxLoginRes.cookies);

        if (initUser) {
            await this.awakenUser();
        }

        this.isLoggedInKhux = true;

        return khuxLoginRes;
    }

    async loginDr() {
        const payload = this.encryptUri(this.getSelfStatus(), '\x06');
        return this.performRequest({
            method: 'POST',
            path:'/dark/login?m=2',
        }, payload);
    }

    async awakenUser() {
        const tutorialStatusRes = await this.getTutorialStatus();

        const userAwakenBody = this.encryptJson(this.getSelfStatus());
        const userAwakenRes = await this.performRequest({
            method: 'PUT',
            path: '/user/awakening?m=1',
        }, userAwakenBody);

        const userRes = await this.getUserData();
        const userStartRes = await this.getUserStart();            
    }

    async getTutorialStatus() {
        return this.performRequest('/tutorial/status', 0, '\x05');
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
            path: `/stage/start?m=1&i=${this.getSavedUserId()}`,
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
            path: `/stage/retire?m=1&i=${this.getSavedUserId()}`,
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
            path: `pet/expedition/recover?m=1&i=${this.getSavedUserId()}&${this.encryptUri(this.getSelfStatus())}`,
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
            path: `/user/chat?m=1&i=${this.getSavedUserId()}&${this.encryptUri(this.getSelfStatus())}`,
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
        return this.performRequest('/user/stone', 0, '\x05');
    }

    async getUserData(updateUserData = true) {
        const userDataRes = await this.performRequest('/user', 0, '\x06');
        
        if (updateUserData) {
            // Track userData for future requests
            this.userData = userDataRes.body.userData;
        }
        return userDataRes;
    }

    async getUserStart() {
        // There is more data included in v= body, but it's encoded
        return this.performRequest('/user/start', 0, '\t');    
    }

    async getUserChat() {
        return this.performRequest('/user/chat', 0, '\x06');
    }

    async getUserMedals() {
        return this.performRequest('/user/medal', 0, '\x05');
    }

    async getParty() {
        return this.performRequest('/party', 0, '\x06');
    }

    async getUserShop() {
        return this.performRequest('/user/shop', 0, '\x07');
    }

    async getUserOptions() {
        return this.performRequest('/user/option', 0, '\x06');
    }

    async getPetProfile() {
        return this.performRequest('/pet/profile', 0, '\b');
    }

    async getPetCoordinateParts() {
        return this.performRequest('/pet/coordinate/parts', 0, '\x05');
    }

    async getPetCoordinateAll() {
        return this.performRequest('/pet/coordinate/all', 0, '\x06');
    }

    async getUserMission() {
        return this.performRequest('/user/mission', 0, '\x06');
    }

    async deletePvpLock() {
        const payload = this.encryptUri(this.getSelfStatus(), '\x06');
        return this.performRequest({
            method: 'DELETE',
            path: `/pvp/lock?m=1&i=${this.getSavedUserId()}`,
        }, payload);
    }

    async putPassiveList() {
        const payload = this.encryptUri({
            isList: 1,
            ...this.getSelfStatus(),
        }, '\n');
        return this.performRequest({
            method: 'PUT',
            path: `/passive/list?m=1&i=${this.getSavedUserId()}`,
        }, payload);
    }

    async putEmblemList() {
        const payload = this.encryptUri(this.getSelfStatus(), '\x06');
        return this.performRequest({
            method: 'PUT',
            path: `/emblem/list?m=1&i=${this.getSavedUserId()}`,
        }, payload);
    }

    async getUserSphere() {
        return this.performRequest('/user/sphere', 0, '\x05');
    }

    async getUserSkill() {
        return this.performRequest('/user/skill', 0, '\x05');
    }

    async getUserMaterial() {
        return this.performRequest('/user/material', 0, '\x05');
    }

    async getUserKeyblade() {
        return this.performRequest('/user/keyblade', 0, '\x05');
    }

    async getUserDeck() {
        return this.performRequest('/user/deck', 0, '\x05');
    }

    async getKeybladeSubslot() {
        return this.performRequest('/keyblade/subslot', 0, '\x05');
    }

    async getUserAvatarAll() {
        return this.performRequest('/user/avatar/all', 0, '\x06');
    }

    async getUserAvatarParts() {
        return this.performRequest('/user/avatar/parts', 0, '\x05');
    }

    async getUserTitle() {
        return this.performRequest('/user/title', 0, '\x06');
    }

    async getUserLink() {
        return this.performRequest('/user/link', 0, '\x06');
    }

    async getUserSupport() {
        return this.performRequest('/user/support', 0, '\x06');
    }

    async getPartyMemberList() {
        const payload = this.encryptUri({
            getDetail: 1,
            platformType: 1,
            ...this.getSelfStatus(),
        }, '\x07');
        return this.performRequest({
            path: `/party/member/list?m=1i=${this.getSavedUserId()}&${payload}`,
        });
    }

    async getUserProfile(userId) {
        const payload = this.encryptUri({
            userId,
            ...this.getSelfStatus(),
        }, '\x06');
        return this.performRequest({
            path: `/user/profile?m=1i=${this.getSavedUserId()}&${payload}`,
        })
    }

    async getLsiGames() {
        return this.performRequest('/lsi/game', 0, '\x05');
    }

    async getStageData() {
        return this.performRequest('/stage/160310', 0, '\x05');
    }

    async getProudStageData() {
        return this.performRequest('/stage/hard', 0, '\x05');
    }

    async getEventStageData(eventCategory) {
        const payload = this.encryptUri({
            eventCategory,
            ...this.getSelfStatus(),
        }, '\x04');
        return this.performRequest({
            path: `/stage/event?m=1&i=${this.getSavedUserId()}&${payload}`,
        });
    }

    async getDarkUser() {
        const darkUserRes = await this.performRequest('/dark/user', 0, '\x06');
        const { ret, ...darkUser } = darkUserRes.body;
        this.darkUser = darkUser;
        return darkUserRes;
    }

    async getDarkUserOptions() {
        return this.performRequest('/dark/user/option', 0, '\x05');
    }

    async getDarkUserCards() {
        return this.performRequest('/dark/user/card', 0, '\x05');
    }

    async getDarkMaterial() {
        return this.performRequest('/dark/material', 0, '\x06');
    }

    async getDarkMaterialEquipment() {
        return this.performRequest('/dark/material/equip', 0, '\x05');
    }

    async getDarkTutorialStatus() {
        return this.performRequest('/dark/tutorial/status', 0, '\x05');
    }

    async getDarkBook() {
        const payload = this.encryptUri({
            notUpdate: 1,
            ...this.getSelfStatus(),
        }, '\b');
        return this.performRequest({
            method: 'PUT',
            path: `/dark/book?m=2i=${this.getSavedDarkUserId()}`,
        }, payload);
    }

    async getDarkStage() {
        const payload = this.encryptUri({
            notUpdate: 1,
            ...this.getSelfStatus(),
        }, '\x07');
        return this.performRequest({
            path: `/dark/stage?m=2&i=${this.getSavedDarkUserId()}&${payload}`
        });
    }

    async getDarkStagePve() {
        return this.performRequest('/dark/stage/pve', 0, '\x05');
    }

    // Returns an object that defines all of the user's data
    async getAllUserData() {
        if (this.isNewKhux && this.isNewDr) {
            console.log('Cannot backup data for new users. Did you enter the right UUID and device type?');
            return null;
        }
        let khux;
        let khdr;

        /** ======== Backup KHUX ======== **/
        if (!this.isNewKhux) {
            if (!this.isLoggedInKhux) await this.loginKhux();
            khux = {
                '/user': await this.getUserData(),
                '/user/start': await this.getUserStart(),
                '/user/chat': await this.getUserChat(),
                '/party': await this.getParty(),
                '/user/stone': await this.getJewels(),
                '/user/stop': await this.getUserShop(),
                '/user/option': await this.getUserOptions(),
                '/pet/profile': await this.getPetProfile(),
                '/pet/coordinate/parts': await this.getPetCoordinateParts(),
                '/pet/coordinate/all': await this.getPetCoordinateAll(),
                '/tutorial/status': await this.getTutorialStatus(),
                '/user/mission': await this.getUserMission(),
                '/pvp/lock': await this.deletePvpLock(), // Likely removes PVP lock if you've reached quest 130
                '/passive/list': await this.putPassiveList(),
                '/emblem/list': await this.putEmblemList(),
                '/user/sphere': await this.getUserSphere(),
                '/user/medal': await this.getUserMedals(),
                '/user/skill': await this.getUserSkill(),
                '/user/material': await this.getUserMaterial(),
                '/user/keyblade': await this.getUserKeyblade(),
                '/user/deck': await this.getUserDeck(),
                '/keyblade/subslot': await this.getKeybladeSubslot(),
                '/user/avatar/all': await this.getUserAvatarAll(),
                '/user/avatar/parts': await this.getUserAvatarParts(),
                '/user/title': await this.getUserTitle(),
                '/user/link': await this.getUserLink(),
                '/user/support': await this.getUserSupport(),
                '/party/member/list': await this.getPartyMemberList(),
                '/user/profile': await this.getUserProfile(),
                '/lsi/game': await this.getLsiGames(),
                '/stage/160310': await this.getStageData(),
                '/stage/hard': await this.getProudStageData(),
                '/stage/event': await this.getEventStageData(2),
            };
            khux = cleanSaveObject(khux);
        }

        /** ======== Backup KHDR ======== **/
        if (!this.isNewDr) {
            // Need to aquire a new session
            await this.init(1);
            await this.loginDr();
            khdr = {
                '/dark/user': await this.getDarkUser(),
                '/user/start': await this.getUserStart(),
                '/dark/user/options': await this.getDarkUserOptions(),
                '/dark/user/cards': await this.getDarkUserCards(),
                '/dark/material': await this.getDarkMaterial(),
                '/dark/material/equip': await this.getDarkMaterialEquipment(),
                '/dark/tutorial/status': await this.getDarkTutorialStatus(),
                '/dark/book': await this.getDarkBook(),
                '/dark/stage': await this.getDarkStage(),
                '/dark/stage/pve': await this.getDarkStage(),
            };
            khdr = cleanSaveObject(khdr);
        }

        return { khux, khdr };
    }
}

module.exports = {
    KHUXClient,
};