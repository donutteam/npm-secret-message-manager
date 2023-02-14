//
// Imports
//

import crypto from "node:crypto";

//
// Class
//

export interface SecretMessageManagerOptions
{
	/** The method to use. Optional, defaults to "aes-256-cbc". */
	algorithm? : string;

	/** The length of initialization vectors. Optional, defaults to 16. */
	initializationVectorLength? : number;

	/** The encryption key. */
	key : string;
}

/**
 * A class for easily encrypting and decrypting secret messages.
 * 
 * This is based upon encryption.js by Tiriel on GitHub.
 * 
 * @see https://gist.github.com/Tiriel/bff8b06cb3359bba5f9e9ba1f9fc52c0
 */
export class SecretMessageManager
{
	/** The algoritm to use. */
	algorithm = "aes-256-cbc";

	/** The length of initialization vectors. */
	initializationVectorLength = 16;

	/** The encryption key. */
	key;

	/**
	 * Constructs a new SecretMessageManager.
	 * 
	 * @author Loren Goodwin
	 */
	constructor(options : SecretMessageManagerOptions)
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
	 * @param plainText The plain text to encrypt.
	 * @returns The encrypted text.
	 * @author Loren Goodwin
	 * @author Tiriel
	 */
	encrypt(plainText : string) : string
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
	 * @param encryptedMessage The encrypted text to decrypt.
	 * @returns The decrypted text.
	 * @author Loren Goodwin
	 * @author Tiriel
	 */
	decrypt(encryptedMessage : string) : string
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