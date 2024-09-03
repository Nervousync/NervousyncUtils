/*
 * Licensed to the Nervousync Studio (NSYC) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.nervousync.zip.crypto.impl.aes;

import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import org.bouncycastle.crypto.BlockCipher;
import org.nervousync.commons.Globals;
import org.nervousync.exceptions.crypto.CryptoException;
import org.nervousync.exceptions.utils.DataInvalidException;
import org.nervousync.security.api.SecureAdapter;
import org.nervousync.security.digest.BaseDigestAdapter;
import org.nervousync.utils.ConvertUtils;
import org.nervousync.utils.SecurityUtils;
import org.nervousync.exceptions.zip.ZipException;
import org.nervousync.utils.RawUtils;

/**
 * AES Crypto
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 2, 2017 11:16:18 AM $
 */
public class AESCrypto {

	/**
	 * Salt data array
	 */
	private byte[] saltBytes;

	/**
	 * key length
	 */
	private int keyLength;
	/**
	 * mac length
	 */
	private int macLength;
	/**
	 * salt length
	 */
	int saltLength;

	/**
	 * current password bytes
	 */
	byte[] derivedPasswordVerifier = null;

	/**
	 * nonce
	 */
	int nonce = 1;
	/**
	 * loop count
	 */
	int loopCount = 0;

	/**
	 * iv bytes
	 */
	byte[] iv = null;
	/**
	 * count block bytes
	 */
	byte[] countBlock = null;

	/**
	 * AES engine
	 */
	AESEngine aesEngine = null;
	BlockCipher aesCipher = null;
	/**
	 * MacBasedPRF instance
	 */
	SecureAdapter macBasedPRF = null;
//	private final boolean forEncryption;

	/**
	 * Instantiates a new Aes crypto.
	 */
	protected AESCrypto() {
	}

	/**
	 * Verify given password
	 *
	 * @param aesStrength   AES key strength
	 * @param salt          salt bytes
	 * @param password      password
	 * @param passwordBytes password bytes
	 * @return verify result
	 */
	public static boolean verifyPassword(int aesStrength, byte[] salt, char[] password, byte[] passwordBytes)
			throws ZipException {
		if (password == null || password.length == 0 || passwordBytes == null || passwordBytes.length == 0) {
			return Boolean.FALSE;
		}
		AESCrypto aesCrypto = new AESCrypto();
		aesCrypto.preInit(aesStrength);
		aesCrypto.init(salt, password);
		return aesCrypto.verifyPassword(passwordBytes);
	}

	/**
	 * Get salt bytes byte [ ].
	 *
	 * @return the saltBytes
	 */
	public byte[] getSaltBytes() {
		return saltBytes == null ? new byte[0] : saltBytes.clone();
	}

	/**
	 * Prepare initialize
	 *
	 * @param aesStrength AES key strength
	 */
	void preInit(int aesStrength) throws ZipException {
		this.iv = new byte[Globals.AES_BLOCK_SIZE];
		this.countBlock = new byte[Globals.AES_BLOCK_SIZE];

		switch (aesStrength) {
			case Globals.AES_STRENGTH_128:
				this.keyLength = 16;
				this.macLength = 16;
				this.saltLength = 8;
				break;
			case Globals.AES_STRENGTH_192:
				this.keyLength = 24;
				this.macLength = 24;
				this.saltLength = 12;
				break;
			case Globals.AES_STRENGTH_256:
				this.keyLength = 32;
				this.macLength = 32;
				this.saltLength = 16;
				break;
			default:
				throw new ZipException(0x0000001B0005L, "Invalid_Key_Strength_AES_Zip_Error");
		}
	}

	/**
	 * Initialize by given password
	 *
	 * @param password password
	 * @throws ZipException the zip exception
	 */
	void init(char[] password) throws ZipException {
		if (password == null || password.length == 0) {
			throw new ZipException(0x0000001B0006L, "Invalid_Password_Zip_Error");
		}
		this.generateSalt();
		try {
			this.initCrypto(password);
		} catch (CryptoException e) {
			throw new ZipException(0x0000001B000AL, "Init_Crypto_Zip_Error", e);
		}
	}

	/**
	 * Initialize by given password and salt
	 *
	 * @param salt     salt bytes
	 * @param password password char arrays
	 * @throws ZipException the zip exception
	 */
	void init(byte[] salt, char[] password) throws ZipException {
		if (password == null || password.length == 0) {
			throw new ZipException(0x0000001B0006L, "Invalid_Password_Zip_Error");
		}
		this.saltBytes = salt == null ? new byte[0] : salt.clone();
		try {
			this.initCrypto(password);
		} catch (CryptoException e) {
			throw new ZipException(0x0000001B000AL, "Init_Crypto_Zip_Error", e);
		}
	}

	/**
	 * Process data.
	 *
	 * @param buff  the buff
	 * @param index the index
	 */
	void processData(byte[] buff, int index) throws ZipException, DataInvalidException {
		this.iv = new byte[16];
		RawUtils.writeInt(this.iv, ByteOrder.LITTLE_ENDIAN, this.nonce);
		this.aesEngine.processBlock(this.iv, this.countBlock);

		for (int j = 0; j < this.loopCount; j++) {
			buff[index + j] = (byte) (buff[index + j] ^ this.countBlock[j]);
		}
		this.nonce++;
	}

	/**
	 * Derive key
	 *
	 * @param saltBytes salt bytes
	 * @param password  password
	 * @param dkLen     length
	 * @return processed data bytes
	 */
	private byte[] deriveKey(byte[] saltBytes, char[] password, int dkLen)
			throws CryptoException, DataInvalidException {
		//	PBKDF2
		if (password == null || password.length == 0) {
			throw new NullPointerException();
		}
		byte[] passwordBytes = RawUtils.charArrayToByteArray(password);
		BaseDigestAdapter digestProvider = (BaseDigestAdapter) SecurityUtils.HmacSHA1(passwordBytes);

		if (dkLen == 0) {
			dkLen = digestProvider.macLength();
		}

		if (saltBytes == null) {
			saltBytes = new byte[0];
		}

		int length = digestProvider.macLength();
		int l = ceil(dkLen, length);
		int r = dkLen - (l - 1) * length;
		byte[] tempBytes = new byte[l * length];
		int offset = 0;
		for (int i = 1; i <= l; i++) {
			process(digestProvider, tempBytes, offset, saltBytes, i);
			offset += length;
		}

		if (r < length) {
			byte[] bytes = new byte[dkLen];
			System.arraycopy(tempBytes, 0, bytes, 0, dkLen);
			return bytes;
		}
		return tempBytes;
	}

	/**
	 * Verify given password
	 *
	 * @param password password
	 * @return verify result
	 */
	boolean verifyPassword(byte[] password) throws ZipException {
		if (this.derivedPasswordVerifier == null) {
			throw new ZipException(0x0000001B0007L, "Invalid_Derived_Password_Verifier_Zip_Error");
		}

		return Arrays.equals(password, this.derivedPasswordVerifier);
	}

	private static int ceil(int a, int b) {
		int m = 0;
		if (a % b > 0) {
			m = 1;
		}
		return a / b + m;
	}

	private static void process(BaseDigestAdapter baseDigestProvider,
	                            byte[] dest, int offset, byte[] source, int blockIndex)
			throws CryptoException, DataInvalidException {
		int length = baseDigestProvider.macLength();
		byte[] tempBytes = new byte[length];

		byte[] intTmpBytes = new byte[source.length + 4];
		System.arraycopy(source, Globals.INITIALIZE_INT_VALUE, intTmpBytes, Globals.INITIALIZE_INT_VALUE, source.length);
		RawUtils.writeInt(intTmpBytes, source.length, blockIndex);

		for (int i = 0; i < 1000; i++) {
			intTmpBytes = baseDigestProvider.finish(intTmpBytes);
			XOR(tempBytes, intTmpBytes);
		}
		System.arraycopy(tempBytes, Globals.INITIALIZE_INT_VALUE, dest, offset, length);
	}

	private static void XOR(byte[] dest, byte[] source) {
		for (int i = 0; i < dest.length; i++) {
			dest[i] ^= source[i];
		}
	}

	/**
	 * Initialize crypto
	 *
	 * @param password password
	 */
	private void initCrypto(char[] password) throws CryptoException, ZipException {
		byte[] keyBytes;
		try {
			keyBytes = this.deriveKey(this.saltBytes, password,
					this.keyLength + this.macLength + Globals.PASSWORD_VERIFIER_LENGTH);
		} catch (DataInvalidException e) {
			throw new ZipException(0x0000001B000AL, "Init_Crypto_Zip_Error", e);
		}

		if (keyBytes.length != (this.keyLength + this.macLength + Globals.PASSWORD_VERIFIER_LENGTH)) {
			throw new ZipException(0x0000001B0008L, "Invalid_Derived_Key_Zip_Error");
		}

		byte[] aesKey = new byte[this.keyLength];
		byte[] macKey = new byte[this.macLength];
		this.derivedPasswordVerifier = new byte[Globals.PASSWORD_VERIFIER_LENGTH];

		System.arraycopy(keyBytes, Globals.INITIALIZE_INT_VALUE, aesKey, Globals.INITIALIZE_INT_VALUE, this.keyLength);
		System.arraycopy(keyBytes, this.keyLength, macKey, Globals.INITIALIZE_INT_VALUE, this.macLength);
		System.arraycopy(keyBytes, (this.keyLength + this.macLength),
				this.derivedPasswordVerifier, Globals.INITIALIZE_INT_VALUE, Globals.PASSWORD_VERIFIER_LENGTH);

		System.out.println(ConvertUtils.toHex(aesKey));
		System.out.println(ConvertUtils.toHex(macKey));
		this.aesEngine = new AESEngine(aesKey);
		this.aesCipher = org.bouncycastle.crypto.engines.AESEngine.newInstance();
//		this.aesCipher.init(this.forEncryption, );
		this.macBasedPRF = SecurityUtils.HmacSHA1(macKey);
	}

	/**
	 * Generate salt data
	 *
	 * @throws ZipException if salt length was invalid
	 */
	private void generateSalt() throws ZipException {
		int rounds = this.saltLength / 4;
		if (rounds < 2 || rounds > 4) {
			throw new ZipException(0x0000001B0009, "Invalid_Salt_Length_Zip_Error");
		}

		this.saltBytes = new byte[this.saltLength];
		for (int i = 0; i < rounds; i++) {
			Random random = new SecureRandom();
			int temp = random.nextInt();
			this.saltBytes[i * 4] = (byte) (temp >> 24);
			this.saltBytes[1 + i * 4] = (byte) (temp >> 16);
			this.saltBytes[2 + i * 4] = (byte) (temp >> 8);
			this.saltBytes[3 + i * 4] = (byte) temp;
		}
	}
}
