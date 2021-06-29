const process = require('process');
const util = require('util');
const commandLineArgs = require('command-line-args');
const readline = require('readline');

const { launchMitm } = require('./mitm');
const { decryptUri, decryptJson, decryptRaw } = require('./encoding');
const { KHUXClient } = require('./client');
const fs = require('fs');

const test_uuid = '<uuid here>';

const optDefs = [
	{ name: 'mitm', type: Boolean },
	{ name: 'decode', type: Boolean },
	{ name: 'key', type: String },
	{ name: 'client', type: Boolean },
	{ name: 'backup', type: String },
	{ name: 'device', type: String },
	{ name: 'quests', type: Boolean },
	{ name: 'os-version', type: String },
	{ name: 'backup-users', type: Boolean },
	{ name: 'min', type: Number },
	{ name: 'max', type: Number },
	{ name: 'uuid', type: String },
];

const opts = commandLineArgs(optDefs);
if (opts.mitm) {
	launchMitm();
} else if (opts.decode) {
	console.log(opts);
	bulkDecode(opts.key);
} else if (opts.client) {
	doClient();
} else if (opts.backup) {
	doBackup(opts.backup, opts.device || 2, opts['os-version'] || 25, opts.quests || false);
} else if (opts['backup-users']) {
	backupUsers(opts);
}

async function doClient() {
	const client = new KHUXClient(test_uuid, 2, '30');
	await client.init();
	await client.loginKhux(true);
}

async function backupUsers(opts) {
	const client = new KHUXClient(opts.uuid, opts.device || 2, opts['os-version'] || '30');
	await client.init();
	await client.loginKhux(true);
	const MIN_ID = opts.min; // Put min id here
	const MAX_ID = opts.max; // Put max ID here
	try {
		fs.mkdirSync('public_user_profiles');
	} catch(e) {}
	for (let id = MIN_ID; id < MAX_ID; id++) {
		const user = {
			'/user/profile': await client.getUserProfile(id),
			'/pet/profile': await client.getUserProfile(id),
		};
		fs.writeFile(`public_user_profiles/${id}.json`, JSON.stringify(user), () => {});
		if (id % 10 === 0) {
			console.log(((id - MIN_ID) / (MAX_ID - MIN_ID) * 100) + '%');
		}
	}
}

async function doBackup(uuid, deviceType = 2, systemVersion = '25', doQuests = false) {
	const client = new KHUXClient(uuid, deviceType, systemVersion);
	await client.init();
	await client.loginKhux()
	const allUserData = await client.getAllUserData(doQuests);
	if (allUserData) {
		fs.writeFileSync('user_data.json', JSON.stringify(allUserData, undefined, 2));
	}
}

async function bulkDecode(key) {
	const rl = readline.createInterface({
		input: process.stdin,
		output: process.stdout,
		terminal: false
	});
	const ask = util.promisify(rl.question).bind(rl);

	let sharedKey = key;
	if (!sharedKey) {
		sharedKey = await ask('Enter shared key: ');
	}

	let depth = 1;

	rl.on('line', (line) => {
		try {
			let payload;
			let rawPayload;
			let doDecrypt = true;
			if (line.startsWith('depth:')) {
				doDecrypt = false;
				depth = parseInt(line.substring('depth:'.length));
			} else if (line.startsWith('file:')) {
				const filename = line.substring('file:'.length);
				line = fs.readFileSync(filename).toString().trim();
			}
			
			if (doDecrypt) {
				if (line.startsWith('v=')) {
					payload = decryptUri(line, sharedKey);
					rawPayload = decryptRaw(decodeURIComponent(line.substring(2)), sharedKey);
				} else {
					payload = decryptJson(line, sharedKey);
					rawPayload = decryptRaw(line, sharedKey);
				}
				console.log({ raw: rawPayload });
				try {
					const parsed = JSON.parse(payload);
					console.dir(parsed, { depth });
				} catch (e) {
					console.log('Invalid');
				}
			}
		} catch (e) {
			console.error(e);
		}
	});
}
