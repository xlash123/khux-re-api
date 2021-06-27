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
];

const opts = commandLineArgs(optDefs);
if (opts.mitm) {
	launchMitm();
} else if (opts.decode) {
	console.log(opts);
	bulkDecode(opts.key);
} else if (opts.client) {
	const client = new KHUXClient(test_uuid);
	client.login().then(() => {
		client.saveAllUserData().then((allUserData) => {
			if (allUserData)
				fs.writeFileSync('user_data.json', JSON.stringify(allUserData, undefined, 2));
		});
	});
} else if (opts.backup) {
	const client = new KHUXClient(opts.backup);
	client.login().then(() => {
		client.saveAllUserData().then((allUserData) => {
			if (allUserData)
				fs.writeFileSync('user_data.json', JSON.stringify(allUserData, undefined, 2));
		});
	});
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

	rl.on('line', (line) => {
		try {
			let payload;
			let rawPayload;
			if (line.startsWith('file:')) {
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
			console.log({ raw: rawPayload });
			try {
				const parsed = JSON.parse(payload);
				console.dir(parsed, { depth: 1 });
			} catch (e) {
				console.log('Invalid');
			}
		} catch (e) {
			console.error(e);
		}
	});
}
