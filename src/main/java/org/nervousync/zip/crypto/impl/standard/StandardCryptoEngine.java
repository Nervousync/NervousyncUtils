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
package org.nervousync.zip.crypto.impl.standard;

/**
 * Standard Crypto Engine
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Nov 29, 2017 4:58:52 PM $
 */
public class StandardCryptoEngine {

	private final int[] keys = new int[3];
	private static final int[] CRC_TABLE = new int[256];

	static {
		for (int i = 0; i < 256; i++) {
			int r = i;
			for (int j = 0; j < 8; j++) {
				if ((r & 1) == 1) {
					r = (r >>> 1) ^ 0xedb88320;
				} else {
					r >>>= 1;
				}
			}
			CRC_TABLE[i] = r;
		}
	}

	/**
	 * Instantiates a new Zip crypto engine.
	 */
	public StandardCryptoEngine() {
	}

	/**
	 * Init keys.
	 *
	 * @param password the password
	 */
	public void initKeys(char[] password) {
		this.keys[0] = 305419896;
		this.keys[1] = 591751049;
		this.keys[2] = 878082192;

		for (char ch : password) {
			this.updateKeys((byte) (ch & 0xFF));
		}
	}

	/**
	 * Update keys.
	 *
	 * @param b the b
	 */
	public void updateKeys(byte b) {
		this.keys[0] = crc32(this.keys[0], b);
		this.keys[1] += this.keys[0] & 0xff;
		this.keys[1] = this.keys[1] * 134775813 + 1;
		this.keys[2] = crc32(this.keys[2], (byte) (this.keys[1] >> 24));
	}

	/**
	 * Decrypt byte.
	 *
	 * @return the byte
	 */
	public byte processByte() {
		int temp = this.keys[2] | 2;
		return (byte) ((temp * (temp ^ 1)) >>> 8);
	}

	private static int crc32(int currentCrc, byte b) {
		return ((currentCrc >>> 8) ^ CRC_TABLE[(currentCrc ^ b) & 0xFF]);
	}
}
