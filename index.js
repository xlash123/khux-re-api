const process = require('process');
const util = require('util');
const commandLineArgs = require('command-line-args');
const readline = require('readline');

const { launchMitm } = require('./mitm');
const { decryptUri } = require('./encoding');
const { login } = require('./client');

const optDefs = [
	{ name: 'mitm', type: Boolean },
	{ name: 'decode', type: Boolean },
	{ name: 'key', type: String },
	{ name: 'client', type: Boolean },
];

const opts = commandLineArgs(optDefs);
if (opts.mitm) {
	launchMitm();
} else if (opts.decode) {
	console.log(opts);
	bulkDecode(opts.key);
} else if (opts.client) {
	login();
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
		const payload = decryptUri(line, sharedKey);
		try {
			const parsed = JSON.parse(payload);
			console.log(parsed);
		} catch (e) {
			console.log('Invalid');
		}
	});
}
