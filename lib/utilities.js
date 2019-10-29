/**
 * Created by osemeodigie on 29/10/2019.
 * @author (Author): Oseme Odigie @oseme-techguy
 * 
 * Utility Functions to Encrypt and Decrypt

 * objective: building to scale
 *
 * @package CoralPayPGPLibrary
 */


const fs = require('fs');
const openpgp = require('openpgp');
const keymanager = require('../keymanager');

openpgp.config.ignore_mdc_error = true;
openpgp.config.use_native = true;

const readFile = (file) => {
	if (fs.existsSync(file)) {
		return fs.readFileSync(file, "utf8");
	}
	throw new Error(`${file} does not exist`);
};


const validateExistence = (obj, ...keys) => {
	const invalid = [];
	for (const key of keys) {
		if (!(obj)[key]) {
			invalid.push(key);
		}
	}
	if (invalid.length > 0) {
		throw new Error(`${invalid.join(", ")} not provided`);
	}
	return true;
};


class Utilities {
	/**
	 * This is the constructor for this library
	 * 
	 * @param {*} config 
	 * Shape of config -> 
	 * {
			privateKeyPath: string;
			passphrase: string;
			publicEncryptionKeyPath: string;
			trace: boolean | Logger;
		}
	 */
	constructor(config) {
		/**
		 * Contains this -> {
				init: boolean;
				encryptionKey: any;
				decryptionKey: any;
				decryptionKeyPublic: any;
			}
		*/
		this.keyStore = { init: false };

		this.trace;
		this.logger = console.log;
		
		validateExistence(
			config,
			'publicEncryptionKeyPath',
			'privateKeyPath'
		);
		if (this.config.passphrase === undefined) {
			this.config.passphrase = '';
		}
		if (this.config.trace === true) {
			this.trace = true;
		} else if (typeof this.config.trace === 'function') {
			this.trace = true;
			this.logger = this.config.trace;
		} else {
			this.trace = false;
		}
	}

	async decryptResponse(body) {
		await this.init();
		if (!body || body === '') {
			return body;
		}
		const binaryEncryptedResponse = Buffer.from(body, 'hex').toString('binary');
		const armored = keymanager.enarmor(binaryEncryptedResponse, 'PGP MESSAGE');
		const msgObj = await openpgp.message.readArmored(armored);
		const decrypted = await openpgp
			.decrypt({
				message: msgObj,
				privateKeys: this.keyStore.decryptionKey,
			})
			.then(plaintext => {
				return plaintext.data;
			});
		try {
			return JSON.parse(decrypted);
		} catch (error) {
			this.log('Response is not a valid JSON');
			return decrypted;
		}
	}

	async encryptRequest(payload) {
		await this.init();
		return await keymanager.encryptRequest(
			JSON.stringify(payload),
			this.keyStore.encryptionKey,
			{ 
				format: 'hex',
				debug: false,
				showVersion: false
			}
		);
	}


	async init() {
		if (this.keyStore.init === true) {
			return true;
		}
		this.keyStore.encryptionKey = await keymanager.importKeys(
			this.config.publicEncryptionKeyPath,
			{
				format: 'hex',
				debug: false,
				showVersion: false
			}
		); // (await openpgp.key.readArmored(CORAL_ENCRYPTION_KEY)).keys;
		this.keyStore.decryptionKey = (await openpgp.key.readArmored(readFile(this.config.privateKeyPath))).keys[0];
		await this.keyStore.decryptionKey.decrypt(this.config.passphrase);
		this.keyStore.init = true;
		return true;
	}

	log(...args) {
		if (this.trace) {
			this.logger(...args);
		}
	}
}

module.exports = {
	Utilities
}
