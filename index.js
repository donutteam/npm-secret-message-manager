//
// Imports
//

import crypto from "crypto";

//
// Class
//

/**
 * A class for easily encrypting and decrypting secret messages.
 * 
 * This is based upon encryption.js by Tiriel on GitHub.
 * 
 * @see https://gist.github.com/Tiriel/bff8b06cb3359bba5f9e9ba1f9fc52c0
 */
export class SecretMessageManager
{
	/**
	 * The algoritm to use.
	 *
	 * @type {String}
	 */
	algorithm = "aes-256-cbc";

	/**
	 * The length of initialization vectors.
	 *
	 * @type {Number}
	 */
	initializationVectorLength = 16;

	/**
	 * The encryption key.
	 * 
	 * @type {String}
	 */
	key;

	/**
	 * Constructs a new SecretMessageManager.
	 * 
	 * @param {Object} options Options for the manager.
	 * @param {String} [options.algorithm] The method to use. Optional, defaults to "aes-256-cbc".
	 * @param {Number} [options.initializationVectorLength] The length of initialization vectors. Optional, defaults to 16.
	 * @param {String} options.key The encryption key.
	 */
	constructor(options)
	{
		if (options.key == null)
		{
			throw new Error("[SecretMessageManager] Must be constructed with a key!");
		}

		this.algorithm = options.algorithm ?? this.algorithm;

		this.initializationVectorLength = options.initializationVectorLength ?? this.initializationVectorLength;

		this.key = options.key;
	}

	/**
	 * Encrypts text with the process' secret message key.
	 *
	 * @param {String} plainText Text to encrypt.
	 * @returns {String} The encrypted text.
	 * @author Loren Goodwin
	 * @author Tiriel
	 */
	encrypt(plainText)
	{
		if (process.versions.openssl <= "1.0.1f")
		{
			throw new Error("[SecretMessageManager] The process' OpenSSL Version is too old, there is a vulnerability to Heartbleed.");
		}

		const keyBuffer = Buffer.from(this.key);

		const initializationVector = crypto.randomBytes(this.initializationVectorLength);

		const cipher = crypto.createCipheriv(this.algorithm, keyBuffer, initializationVector);

		let encrypted = cipher.update(plainText);

		encrypted = Buffer.concat([ encrypted, cipher.final() ]);

		return initializationVector.toString("hex") + ":" + encrypted.toString("hex");
	}

	/**
	 * Decrypts text with the process' secret message key.
	 *
	 * @param {String} encryptedMessage Text to decrypt.
	 * @returns {String} The decrypted text.
	 * @author Loren Goodwin
	 * @author Tiriel
	 */
	decrypt(encryptedMessage)
	{
		const textParts = encryptedMessage.split(":", 2);

		const keyBuffer = Buffer.from(this.key);

		const initializationVector = Buffer.from(textParts[0], "hex");
		const encryptedText = Buffer.from(textParts[1], "hex");

		const decipher = crypto.createDecipheriv(this.algorithm, keyBuffer, initializationVector);

		let decrypted = decipher.update(encryptedText);

		decrypted = Buffer.concat([ decrypted, decipher.final() ]);

		return decrypted.toString();
	}
}