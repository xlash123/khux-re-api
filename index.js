const process = require('process');
const util = require('util');
const commandLineArgs = require('command-line-args');
const readline = require('readline');

const { launchMitm } = require('./mitm');
const { decryptUri, decryptJson, decryptRaw } = require('./encoding');
const { KHUXClient } = require('./client');
const fs = require('fs');

const test_uuid = '950f4192-f28a-469b-b602-dac828f0548a';

const optDefs = [
	{ name: 'mitm', type: Boolean },
	{ name: 'decode', type: Boolean },
	{ name: 'key', type: String },
	{ name: 'client', type: Boolean },
	{ name: 'backup', type: String },
	{ name: 'device', type: String },
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
	doBackup(opts.backup, opts.device || 2);
}

async function doClient() {
	const client = new KHUXClient(test_uuid);
	await client.init();
	await client.loginKhux();
	// Do stuff here
}

async function doBackup(uuid, deviceType = 2) {
	const client = new KHUXClient(uuid, deviceType);
	await client.init();
	await client.loginKhux()
	const allUserData = await client.getAllUserData();
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
			
			if (line.startsWith('v=')) {
				payload = decryptUri(line, sharedKey);
				rawPayload = decryptRaw(decodeURIComponent(line.substring(2)), sharedKey);
			} else {
				payload = decryptJson(line, sharedKey);
				rawPayload = decryptRaw(line, sharedKey);
			}
			if (doDecrypt) {
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
