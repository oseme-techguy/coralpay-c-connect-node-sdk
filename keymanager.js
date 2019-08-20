/**
 * Created by osemeodigie on 13/05/2018.
 * objective: building to scale
 * 
 * @author (Author): Oseme Odigie @oseme-techguy
 *
 * @package CoralPayPGPLibrary
 */

const fs = require('fs');
const GPG = require('gpg');
const shelljs = require('shelljs');
const misc = require('locutus/php/misc');




/**
 * GPG status output file descriptor. The status file descriptor outputs
 * detailed information for many GPG commands. See the second section of
 * the file <b>doc/DETAILS</b> in the
 * {@link http://www.gnupg.org/download/ GPG package} for a detailed
 * description of GPG's status output.
 */
const FD_STATUS = 3;

/**
 * Command input file descriptor. This is used for methods requiring
 * passphrases.
 */
const FD_COMMAND = 4;


const defaultArguments = [
 // '--status-fd ' + FD_STATUS,
 // '--command-fd ' + FD_COMMAND,
 '--exit-on-status-write-error',
 '--no-permission-warning',
  '--no-secmem-warning',
  '--no-tty',
  '--no-default-keyring', // ignored if keying files are not specified
  '--no-options'          // prevent creation of ~/.gnupg directory
];


/**
 * Used to import a key into the GPG keychain.
 * 
 * @param {*} keyContentToImport 
 * @param {*} importOptions 
 */
const importKeys = async (keyContentToImport, importOptions = {}) => {
  const argOptions = importOptions || {
      debug: false
  };
  return new Promise((resolve, reject) => {
    GPG.importKey(keyContentToImport, function(importError, result, fingerprint) {
      if(!importError) {
        if((argOptions.debug != undefined) && argOptions.debug) {
          console.log(`\n\nSuccesfully imported the key!!! \n\nImported Key Data: \n${result} \n\n`);
        }

        const keyId = (fingerprint != null && fingerprint != undefined) ? fingerprint : null;
        return resolve(keyId);
      }

      if((argOptions.debug != undefined) && argOptions.debug) {
        console.log(`\nError occurred while importing key!\n`);
      }
      return reject(new Error(`Error occurred while importing key!`));
    });
  });
};

exports.importKeys = importKeys;


/**
 * This method is used to encrypt the request to be sent to Cgate.
 * 
 * @param {*} plainMessage - the plain request to encrypt
 * @param {*} keyIdForPublicKey - the Long/Short ID for the imported public key
 * @param {*} encryptOptions - options to control how the output is generated
 */
const _encryptRequest = async (plainMessage, keyIdForPublicKey, encryptOptions = {}) => {
  const argOptions = encryptOptions || {
      homedir: null,
      armor: true,
      debug: false,
      format: 'binary', // binary , hex or armor
      showVersion: false
  };

  if(keyIdForPublicKey == undefined || keyIdForPublicKey == null) {
    if((argOptions.debug != undefined) && argOptions.debug) {
      console.log(`Error: Key Not Found with Id`);
    }
    throw new Error(`Error: Key Not Found with Id`);
    return;
  }

  let optionArgs = [
    '--default-key', keyIdForPublicKey,
    '--recipient', keyIdForPublicKey,
    '--trust-model', 'always' // so we don't get "no assurance this key belongs to the given user"
  ];

  if((argOptions.homedir != undefined) && (argOptions.homedir != null) && argOptions.homedir) {
    optionArgs.push('--homedir').push(argOptions.homedir);
  }

  if(((argOptions.armor != undefined) && argOptions.armor) || 
    ((argOptions.format != undefined) && argOptions.format.toLowerCase() === 'armor')) {
    optionArgs.push('--armor');
  }

  // Add the default options
  optionArgs = optionArgs.concat(defaultArguments);

  if((argOptions.debug != undefined) && argOptions.debug) {
    console.log(`\nCalling GPG with options: \n${JSON.stringify(optionArgs)}\n`);
  }

  return new Promise((resolve, reject) => {
    GPG.encrypt(plainMessage, optionArgs, function(error, encryptedBuffer) {
        if(error) {
          if((argOptions.debug != undefined) && argOptions.debug) {
            console.log(`\nError occurred while encrypting request with GPG. Error: \n${error}\n`);
          }
          reject(error);
        }
        const outputString = ((argOptions.format != undefined) && argOptions.format.toLowerCase() === 'hex') ? 
          encryptedBuffer.toString("hex") : 
          encryptedBuffer.toString();
    
        if((argOptions.debug != undefined) && argOptions.debug) {
          console.log(`\nSuccessfully Encrypted With GPG: \n\n${outputString}\n`);
        }
    
        resolve(outputString);
      });
  })
};

exports.encryptRequest = _encryptRequest;



/**
 * This method is used to decrypt the response that is received from Cgate.
 * 
 * @param {*} encryptedResponse - the encrypted response to decrypt
 * @param {*} keyIdForPrivateKey - the Long/Short ID for the imported public key 
 * @param {*} passphrase - the passphrase associated with the Private key
 * @param {*} decryptOptions - options to control how the decryption process flows
 */
const _decryptRequest = async (encryptedResponse, keyIdForPrivateKey, passphrase, decryptOptions = {}) => {
  const argOptions = decryptOptions || {
      homedir: null,
      armor: true,
      debug: false,
      format: 'binary', // plain, hex, or armor
      showVersion: false
  };

  if(keyIdForPrivateKey == undefined || keyIdForPrivateKey == null) {
    if((argOptions.debug != undefined) && argOptions.debug) {
      console.log(`Error: Key Not Found with Id`);
    }
    throw new Error(`Error: Key Not Found with Id`);
    return;
  }

  let optionArgs = [
    '--skip-verify',
    '--ignore-mdc-error',
   // '--options /dev/null', // ignore any saved options
    //'--pinentry-mode loopback', // Since 2.1.13 we can use "loopback mode" instead of gpg-agent
    '--default-key', keyIdForPrivateKey,
    '-u', keyIdForPrivateKey,
    '--trust-model', 'always', // so we don't get "no assurance this key belongs to the given user"
    // 'echo your_password | gpg --batch --yes --passphrase-fd 0',
    '--batch',// '--quiet',
    '--yes', 
    // '--passphrase-file <(echo password)',
    '--passphrase', passphrase
  ];

  if((argOptions.homedir != undefined) && (argOptions.homedir != null) && argOptions.homedir) {
    optionArgs.push('--homedir').push(argOptions.homedir);
  }

  if(((argOptions.armor != undefined) && argOptions.armor) || 
    ((argOptions.format != undefined) && argOptions.format.toLowerCase() === 'armor')) {
    optionArgs.push('--armor');
  }

  // Add the default options
  optionArgs = optionArgs.concat(defaultArguments);

  if((argOptions.debug != undefined) && argOptions.debug) {
    console.log(`\nCalling GPG with options: \n${JSON.stringify(optionArgs)}\n`);
  }

  const binaryEncryptedResponse = Buffer.from(encryptedResponse, 'hex').toString('binary');
  const armoredBinMessage = enarmor(binaryEncryptedResponse, 'PGP MESSAGE');
  // console.log("\n\nThe Armored Message:\n\n", armoredBinMessage, '\n\n')
  // return;

  // -u ${keyIdForPrivateKey} --batch --passphrase-fd 0`
  // const decryptCommand = `echo "password" | gpg --decrypt`;
  // shelljs.exec(decryptCommand, function(code, stdout, stderr) {
  //   console.log('Exit Code: ', code);
  //   console.log('Program Output: ', stdout);
  //   console.log('Program stderr: ', stderr);

  // });
  // return;
  return new Promise((resolve, reject)=> {
    GPG.decrypt(armoredBinMessage, optionArgs, function(error, decryptedBuffer) {
        if(error) {
          if((argOptions.debug != undefined) && argOptions.debug) {
            console.log(`\nError occurred while decrypting response with GPG.\n${error}\n`);
          }
          reject(error);
        }
        const outputString = ((argOptions.format != undefined) && argOptions.format.toLowerCase() === 'hex') ? 
          decryptedBuffer.toString("hex") : 
          decryptedBuffer.toString();
    
        if((argOptions.debug != undefined) && argOptions.debug) {
          console.log(`\nSuccessfully Decrypted With GPG: \n\n${outputString}\n`);
        }
    
        resolve(outputString);
      });
  })
};

exports.decryptRequest = _decryptRequest;


/**
 * Utility function to convert Uint8 array to a binary string.
 * 
 * @param {*} u8Array 
 */
const convertUint8ArrayToBinaryString = (u8Array) => {
	var i, len = u8Array.length, binaryString = "";
	for (i=0; i<len; i++) {
		binaryString += String.fromCharCode(u8Array[i]);
	}
	return binaryString;
}

/**
 * Utility function to convert from a binary string to an Uint8 array.
 * 
 * @param {*} binaryString 
 */
const convertBinaryStringToUint8Array = (binaryString) => {
	var i, len = binaryString.length, u8_array = new Uint8Array(len);
	for (var i = 0; i < len; i++) {
		u8_array[i] = binaryString.charCodeAt(i);
	}
	return u8_array;
}

  /**
   * Ord function
   * @param {*} str 
   */
  const ord = (str) => {
    return str.charCodeAt(0);
  }


  /**
   * @see http://tools.ietf.org/html/rfc4880#section-6.2
   */
  const header = (marker) => {
      return '-----BEGIN ' + marker.toUpperCase() + '-----';
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-6.2
   */
  const footer = (marker) => {
      return '-----END ' + marker.toUpperCase() + '-----';
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-6
   * @see http://tools.ietf.org/html/rfc4880#section-6.1
   */
  const crc24 = (data) => {
      crc = 0x00b704ce;
      for (i = 0; i < data.length; i += 1) {
          crc ^= (ord(data[i]) & 255) << 16;
          for (j = 0; j < 8; j += 1) {
              crc <<= 1;
              if (crc & 0x01000000) {
                  crc ^= 0x01864cfb;
              }
          }
      }
      return crc & 0x00ffffff;
  }

  /**
   * Method to perform word wrap operation on a string
   * 
   * @param {*} word 
   * @param {*} width 
   * @param {*} breakChar 
   * @param {*} shouldCut 
   */
  const wordwrap = (word, width, breakChar, shouldCut) => {
    breakChar = breakChar || 'n';
    width = width || 76;
    shouldCut = shouldCut || false;

    if(!word) {
      return word;
    }

    const wordLength = word.length;
    let startIndex = 0;
    let wrappedWordLines = [];
    while(startIndex < wordLength) {
      const acceptableWidth = ((startIndex + width) > wordLength) ? (wordLength - startIndex) : width;
      wrappedWordLines.push(word.substr(startIndex, acceptableWidth));
      startIndex += width;
    }
    return wrappedWordLines.join(breakChar);
  }

  /**
   * @see http://tools.ietf.org/html/rfc4880#section-6
   * @see http://tools.ietf.org/html/rfc4880#section-6.2
   * @see http://tools.ietf.org/html/rfc2045
   */
  const enarmor = (data, marker = 'MESSAGE', headers = {}) => {
    text = header(marker) + "\n";
    const headerKeys = Object.keys(headers);
    for (i = 0; i < headerKeys.length; i += 1) {
      text += headerKeys[i] + ': ' + headers[headerKeys[i]] + "\n";
    }
    
    const base64Data = Buffer.from(data, 'binary').toString('base64');
    const packDataToUInt32BE = misc.pack('N', crc24(data)); // pack line here
    const base64PackedData = Buffer.from(packDataToUInt32BE.substr(1), 'binary').toString('base64');

    text += "\n" + wordwrap(base64Data, 76, "\n", true);
    text += "\n" + '=' + base64PackedData + "\n";
    text += footer(marker) + "\n";
    return text;
  }

  exports.enarmor = enarmor;
