/**
 * Created by osemeodigie on 19/07/2019.
 * @author (Author): Oseme Odigie @oseme-techguy
 * Co-author: Peter-Smart Olu @iyiolapeter

 * objective: building to scale
 *
 * @package CoralPayPGPLibrary
 */


import fs from 'fs';
import { IncomingHttpHeaders } from 'http';
import * as openpgp from 'openpgp';
import path from 'path';
import { RequestAPI, RequiredUriUrl } from 'request';
import request from 'request-promise';
import * as keymanager  from '../keymanager';

openpgp.config.ignore_mdc_error = true;
openpgp.config.use_native = true;

const INVOKE_REFERENCE_API = "api/invokereference";
const QUERY_TRANSACTION_API = "api/statusquery";

const CORAL_ENCRYPTION_KEY = fs.readFileSync(path.resolve(__dirname, './../assets/coralpay.pub.key'), 'utf8');

export const METHOD = {
	POST = "POST",
	GET = "GET",
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


export class CoralPayCConnect {
	get baseUrl() {
		return this.config.cConnectServiceBaseUrl;
	}

	/**
	 * Contains this -> {
			init: boolean;
			encryptionKey: any;
			decryptionKey: any;
			decryptionKeyPublic: any;
		}
	 */
	keyStore = { init: false };

	trace;
	logger = console.log;
	baseRequest;

	/**
	 * This is the constructor for this library
	 * 
	 * @param {*} config 
	 * Shape of config -> 
	 * {
			privateKeyPath: string;
			passphrase: string;
			cConnectPublicEncryptionKeyPath: string;
			merchantId: string;
			terminalId: string;
			userName: string;
			password: string;
			trace: boolean | Logger;
		}
	 */
	constructor(config) {
		validateExistence(
			config,
			'cConnectServiceBaseUrl',
			'privateKeyPath',
			'merchantId',
			'terminalId',
			'userName',
			'password'
		);
		if (this.config.passphrase === undefined) {
			this.config.passphrase = '';
		}
		if (this.config.cConnectPublicEncryptionKeyPath === undefined) {
			this.config.cConnectPublicEncryptionKeyPath = CORAL_ENCRYPTION_KEY;
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
		this.log('Encrypted Form: ', body);
		const self = this;
		const response = await this.baseRequest({
			method,
			uri,
			body,
			headers,
			transform: async (resbody, res) => {
				self.log('Raw Response: ', resbody);
				return {
					statusCode: res.statusCode,
					headers: res.headers,
					body: await self.decryptResponse(resbody),
				};
			},
		});
		this.log('Response from CGATE', response);
		return response;
	}


	/**
	 * This is used to retrive a ussd payment reference code from Cgate.
	 * 
	 * @param {*} payload  - { Amount as Number , TraceID as String, Channel as String }
	 */
	async invokeReference(payload) {
		validateExistence(payload, 'Channel', 'Amount');
		const { Channel, Amount, TraceID } = payload;
		const { userName, password, terminalId, merchantId } = this.config;
		const body = {
			RequestHeader: {
				UserName,
				Password,
			},
			RequestDetails: {
				TerminalId,
				Channel,
				Amount,
				MerchantId,
			},
		};
		if (TraceID) {
			(body.RequestDetails).TraceID = TraceID;
		}
		return await this.customRequest(METHOD.POST, INVOKE_REFERENCE_API, body);
	}

	/**
	 * This is used to query for the status of a transaction
	 * 
	 * @param {*} payload - { Amount as Number , TransactionID as String }
	 */
	async queryTransaction(payload) {
		validateExistence(payload, 'Amount', 'TransactionID');
		const { Amount, TransactionID } = payload;
		const { userName, password, terminalId, merchantId } = this.config;
		const body = {
			RequestHeader: {
				UserName,
				Password,
			},
			RequestDetails: {
				TerminalId,
				MerchantId,
				Amount,
				TransactionID,
			},
		};
		return await this.customRequest(METHOD.POST, QUERY_TRANSACTION_API, body);
	}

	async init() {
		if (this.keyStore.init === true) {
			return true;
		}
		this.keyStore.encryptionKey = await keymanager.importKeys(
			this.config.cConnectPublicEncryptionKeyPath,
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
