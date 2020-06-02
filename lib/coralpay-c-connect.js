/**
 * Created by osemeodigie on 19/07/2019.
 * @author (Author): Oseme Odigie @oseme-techguy
 * Co-author: Peter-Smart Olu @iyiolapeter

 * objective: building to scale
 *
 * @package CoralPayPGPLibrary
 */


const fs = require('fs');
const { IncomingHttpHeaders }  = require('http');
const openpgp = require('openpgp');
const { RequestAPI, RequiredUriUrl } = require('request');
const request = require('request-promise');
const keymanager = require('../keymanager');

openpgp.config.ignore_mdc_error = true;
openpgp.config.use_native = true;

const INVOKE_REFERENCE_API = "api/invokereference";
const QUERY_TRANSACTION_API = "api/statusquery";

const METHOD = {
	POST: "POST",
	GET: "GET",
}


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


class CoralPayCConnect {
	/**
	 * This is the constructor for this library
	 * 
	 * @param {*} config 
	 * Shape of config -> 
	 * {
			privateKeyPath: string;
			passphrase: string;
			cConnectPublicEncryptionKeyPath: string;
			merchant_id: string;
			terminal_id: string;
			username: string;
			password: string;
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
		this.config = config;
		this.logger = console.log;
		this.baseRequest;

		validateExistence(
			config,
			'cConnectServiceBaseUrl',
			'cConnectPublicEncryptionKeyPath',
			'privateKeyPath',
			'merchant_id',
			'terminal_id',
			'username',
			'password'
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
		this.baseRequest = request.defaults({
			baseUrl: this.baseUrl,
			simple: false,
			resolveWithFullResponse: true,
		});
	}

	get baseUrl() {
		return this.config.cConnectServiceBaseUrl;
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
				debug: this.trace,
				showVersion: false
			}
		);
	}

	async customRequest(method, uri, data) {
		await this.init();
		let body = '';
		const headers = {
			'Content-Type': 'text/plain',
		};
		this.log('Base URL: ', this.baseUrl);
		this.log('URI: ', uri);
		this.log('Method: ', method);
		this.log('Headers: ', headers);
		if (data && method === METHOD.POST) {
			this.log('Data: ', JSON.stringify(data, null, 2));
			body = await this.encryptRequest(data);
		}
		this.log('Encrypted Request Sent to Cgate: ', body);
		const self = this;
		const response = await this.baseRequest({
			method,
			uri,
			body,
			headers,
			transform: async (resbody, res) => {
				self.log('\nEncrypted Response from Cgate: ', resbody);
				return {
					statusCode: res.statusCode,
					headers: res.headers,
					body: await self.decryptResponse(resbody),
				};
			},
		});
		this.log('\nResponse from Cgate[Decrypted] ', response);
		return response;
	}


	/**
	 * This is used to retrive a ussd payment reference code from Cgate.
	 * 
	 * @param {*} payload  - { amount as Number , trace_id as String, channel as String }
	 */
	async invokeReference(payload) {
		validateExistence(payload, 'channel', 'amount');
		const { channel, amount, trace_id } = payload;
		const { username, password, terminal_id, merchant_id } = this.config;
		const body = {
			RequestHeader: {
				Username: username,
				Password: password,
			},
			RequestDetails: {
				TerminalId: terminal_id,
				Channel: channel,
				Amount: amount,
				MerchantId: merchant_id,
			},
		};
		if (trace_id) {
			(body.RequestDetails).TraceID = trace_id;
		}
		return await this.customRequest(METHOD.POST, INVOKE_REFERENCE_API, body);
	}

	/**
	 * This is used to query for the status of a transaction
	 * 
	 * @param {*} payload - { amount as Number , transaction_id as String }
	 */
	async queryTransaction(payload) {
		validateExistence(payload, 'amount', 'transaction_id');
		const { amount, transaction_id } = payload;
		const { username, password, terminal_id, merchant_id } = this.config;
		const body = {
			RequestHeader: {
				Username: username,
				Password: password,
			},
			RequestDetails: {
				TerminalId: terminal_id,
				MerchantId: merchant_id,
				Amount: amount,
				TransactionID: transaction_id,
			},
		};
		return await this.customRequest(METHOD.POST, QUERY_TRANSACTION_API, body);
	}

	async init() {
		if (this.keyStore.init === true) {
			return true;
		}
		this.keyStore.encryptionKey = await keymanager.importKeys(
			readFile(this.config.cConnectPublicEncryptionKeyPath),
			{
				format: 'hex',
				debug: this.trace,
				showVersion: false
			}
		).catch(error => this.log('Import Error: ', error)); // (await openpgp.key.readArmored(CORAL_ENCRYPTION_KEY)).keys;
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
	CoralPayCConnect: CoralPayCConnect,
	METHOD: METHOD
}
