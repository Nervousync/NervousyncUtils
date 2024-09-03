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

import org.nervousync.commons.Globals;
import org.nervousync.exceptions.crypto.CryptoException;
import org.nervousync.zip.models.header.LocalFileHeader;
import org.nervousync.exceptions.zip.ZipException;
import org.nervousync.zip.crypto.Decryptor;

/**
 * Decryptor implement of AES
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 2, 2017 10:55:30 AM $
 */
public final class AESDecryptor extends AESCrypto implements Decryptor {

	private byte[] storedMac = null;

	/**
	 * Instantiates a new Aes decryptor.
	 *
	 * @param localFileHeader the local file header
	 * @param salt            the salt
	 * @param passwordBytes   the password bytes
	 * @throws ZipException the zip exception
	 */
	public AESDecryptor(LocalFileHeader localFileHeader,
	                    byte[] salt, byte[] passwordBytes) throws ZipException {
		if (localFileHeader == null) {
			throw new ZipException(0x0000001B000EL, "Null_Local_File_Header_Zip_Error");
		}

		if (localFileHeader.getAesExtraDataRecord() == null) {
			throw new ZipException(0x0000001B0010L, "Invalid_AES_Extra_Data_Zip_Error");
		}

		super.preInit(localFileHeader.getAesExtraDataRecord().getAesStrength());
		this.init(salt, localFileHeader.getPassword());

		if (!this.verifyPassword(passwordBytes)) {
			throw new ZipException(0x0000001B000DL, "Wrong_Password_Zip_Error");
		}
	}

	@Override
	public int decryptData(byte[] buff) throws ZipException {
		return this.decryptData(buff, 0, buff.length);
	}

	@Override
	public int decryptData(byte[] buff, int start, int len) throws ZipException {
		if (this.aesEngine == null) {
			throw new ZipException(0x0000001B0002L, "Not_Initialized_AES_Engine_Zip_Error");
		}
		try {
			for (int i = start; i < (start + len); i += Globals.AES_BLOCK_SIZE) {
				this.loopCount = (i + Globals.AES_BLOCK_SIZE <= (start + len)) ?
						Globals.AES_BLOCK_SIZE : ((start + len) - i);
				this.macBasedPRF.append(buff, i, this.loopCount);
				super.processData(buff, i);
			}
			return len;
		} catch (Exception e) {
			throw new ZipException(0x0000001B000BL, "Decrypt_Crypto_Zip_Error", e);
		}
	}

	/**
	 * Calculate authentication bytes byte [ ].
	 *
	 * @return the byte [ ]
	 * @throws CryptoException the crypto exception
	 */
	public byte[] calculateAuthenticationBytes() throws CryptoException {
		return this.macBasedPRF.finish();
	}

	/**
	 * Gets salt length.
	 *
	 * @return the saltLength
	 */
	public int getSaltLength() {
		return saltLength;
	}

	/**
	 * Get stored mac byte [ ].
	 *
	 * @return the storedMac
	 */
	public byte[] getStoredMac() {
		return storedMac == null ? null : storedMac.clone();
	}

	/**
	 * Sets stored mac.
	 *
	 * @param storedMac the storedMac to set
	 */
	public void setStoredMac(byte[] storedMac) {
		this.storedMac = storedMac == null ? new byte[0] : storedMac.clone();
	}
}
