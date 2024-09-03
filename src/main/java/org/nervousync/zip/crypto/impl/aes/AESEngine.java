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

import org.nervousync.exceptions.utils.DataInvalidException;
import org.nervousync.zip.models.AESExtraDataRecord;
import org.nervousync.zip.models.header.utils.HeaderOperator;
import org.nervousync.exceptions.zip.ZipException;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * AES Engine
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Nov 30, 2017 2:55:56 PM $
 */
public final class AESEngine {

	private int rounds;
	private int[][] workingKeys = null;
	private int C0, C1, C2, C3;

	/**
	 * Instantiates a new Aes engine.
	 *
	 * @param keys the keys
	 * @throws ZipException the zip exception
	 */
	public AESEngine(byte[] keys) throws ZipException {
		this.generateWorkingKeys(keys);
	}

	/**
	 * Process block.
	 *
	 * @param in  the in
	 * @param out the out
	 * @throws ZipException the zip exception
	 */
	public void processBlock(byte[] in, byte[] out) throws ZipException {
		if (this.workingKeys == null) {
			throw new ZipException(0x0000001B0002L, "Not_Initialized_AES_Engine_Zip_Error");
		}

		if (in.length < 16) {
			throw new ZipException(0x0000001B0003L, "Input_Buffer_Too_Short_Zip_Error");
		}

		if (out.length < 16) {
			throw new ZipException(0x0000001B0011L, "Output_Buffer_Too_Short_Zip_Error");
		}

		this.stateIn(in);
		this.encryptBlock();
		this.stateOut(out);
	}

	/**
	 * Process header.
	 *
	 * @param aesExtraDataRecord the aes extra data record
	 * @param headerBytesList    the header bytes list
	 */
	public static void processHeader(AESExtraDataRecord aesExtraDataRecord, List<String> headerBytesList)
			throws ZipException, DataInvalidException {
		HeaderOperator.appendShortToArrayList((short) aesExtraDataRecord.getSignature(), headerBytesList);
		HeaderOperator.appendShortToArrayList((short) aesExtraDataRecord.getDataSize(), headerBytesList);
		HeaderOperator.appendShortToArrayList((short) aesExtraDataRecord.getVersionNumber(), headerBytesList);
		HeaderOperator.copyByteArrayToList(aesExtraDataRecord.getVendorID().getBytes(StandardCharsets.UTF_8), headerBytesList);

		byte[] aesStrengthBytes = new byte[1];
		aesStrengthBytes[0] = (byte) aesExtraDataRecord.getAesStrength();
		HeaderOperator.copyByteArrayToList(aesStrengthBytes, headerBytesList);

		HeaderOperator.appendShortToArrayList((short) aesExtraDataRecord.getCompressionMethod(), headerBytesList);
	}

	private void stateIn(byte[] bytes) {
		int index = 0;

		this.C0 = (bytes[index++] & 0xFF);
		this.C0 |= (bytes[index++] & 0xFF) << 8;
		this.C0 |= (bytes[index++] & 0xFF) << 16;
		this.C0 |= bytes[index++] << 24;

		this.C1 = (bytes[index++] & 0xFF);
		this.C1 |= (bytes[index++] & 0xFF) << 8;
		this.C1 |= (bytes[index++] & 0xFF) << 16;
		this.C1 |= bytes[index++] << 24;

		this.C2 = (bytes[index++] & 0xFF);
		this.C2 |= (bytes[index++] & 0xFF) << 8;
		this.C2 |= (bytes[index++] & 0xFF) << 16;
		this.C2 |= bytes[index++] << 24;

		this.C3 = (bytes[index++] & 0xFF);
		this.C3 |= (bytes[index++] & 0xFF) << 8;
		this.C3 |= (bytes[index++] & 0xFF) << 16;
		this.C3 |= bytes[index] << 24;
	}

	private void encryptBlock() {
		int r = 1;

		this.C0 ^= this.workingKeys[0][0];
		this.C1 ^= this.workingKeys[0][1];
		this.C2 ^= this.workingKeys[0][2];
		this.C3 ^= this.workingKeys[0][3];

		int[] calcBlock;
		while (r < this.rounds - 1) {
			calcBlock = this.calcBlock(r);
			r++;
			this.calcByT0(calcBlock, r);
			r++;
		}

		calcBlock = this.calcBlock(r);
		r++;

		this.calcBySubWord(calcBlock, r);
	}

	private void calcBySubWord(int[] calcBlock, int indexKey) {
		this.C0 = (SUB_WORD_TABLE[calcBlock[0] & 255] & 255) ^ ((SUB_WORD_TABLE[(calcBlock[1] >> 8) & 255] & 255) << 8)
				^ ((SUB_WORD_TABLE[(calcBlock[2] >> 16) & 255] & 255) << 16) ^ (SUB_WORD_TABLE[(calcBlock[3] >> 24) & 255] << 24)
				^ this.workingKeys[indexKey][0];
		this.C1 = (SUB_WORD_TABLE[calcBlock[1] & 255] & 255) ^ ((SUB_WORD_TABLE[(calcBlock[2] >> 8) & 255] & 255) << 8)
				^ ((SUB_WORD_TABLE[(calcBlock[3] >> 16) & 255] & 255) << 16) ^ (SUB_WORD_TABLE[(calcBlock[0] >> 24) & 255] << 24)
				^ this.workingKeys[indexKey][1];
		this.C2 = (SUB_WORD_TABLE[calcBlock[2] & 255] & 255) ^ ((SUB_WORD_TABLE[(calcBlock[3] >> 8) & 255] & 255) << 8)
				^ ((SUB_WORD_TABLE[(calcBlock[0] >> 16) & 255] & 255) << 16) ^ (SUB_WORD_TABLE[(calcBlock[1] >> 24) & 255] << 24)
				^ this.workingKeys[indexKey][2];
		this.C3 = (SUB_WORD_TABLE[calcBlock[3] & 255] & 255) ^ ((SUB_WORD_TABLE[(calcBlock[0] >> 8) & 255] & 255) << 8)
				^ ((SUB_WORD_TABLE[(calcBlock[1] >> 16) & 255] & 255) << 16) ^ (SUB_WORD_TABLE[(calcBlock[2] >> 24) & 255] << 24)
				^ this.workingKeys[indexKey][3];
	}

	private int[] calcBlock(int r) {
		return new int[]{
				T0[this.C0 & 255] ^ shift(T0[(this.C1 >> 8) & 255], 24) ^ shift(T0[(this.C2 >> 16) & 255], 16)
						^ shift(T0[(this.C3 >> 24) & 255], 8) ^ this.workingKeys[r][0],
				T0[this.C1 & 255] ^ shift(T0[(this.C2 >> 8) & 255], 24) ^ shift(T0[(this.C3 >> 16) & 255], 16)
						^ shift(T0[(this.C0 >> 24) & 255], 8) ^ this.workingKeys[r][1],
				T0[this.C2 & 255] ^ shift(T0[(this.C3 >> 8) & 255], 24) ^ shift(T0[(this.C0 >> 16) & 255], 16)
						^ shift(T0[(this.C1 >> 24) & 255], 8) ^ this.workingKeys[r][2],
				T0[this.C3 & 255] ^ shift(T0[(this.C0 >> 8) & 255], 24) ^ shift(T0[(this.C1 >> 16) & 255], 16)
						^ shift(T0[(this.C2 >> 24) & 255], 8) ^ this.workingKeys[r][3]};
	}

	private void calcByT0(int[] calcBlock, int indexKey) {
		this.C0 = T0[calcBlock[0] & 255] ^ shift(T0[(calcBlock[1] >> 8) & 255], 24) ^ shift(T0[(calcBlock[2] >> 16) & 255], 16)
				^ shift(T0[(calcBlock[3] >> 24) & 255], 8) ^ this.workingKeys[indexKey][0];
		this.C1 = T0[calcBlock[1] & 255] ^ shift(T0[(calcBlock[2] >> 8) & 255], 24) ^ shift(T0[(calcBlock[3] >> 16) & 255], 16)
				^ shift(T0[(calcBlock[0] >> 24) & 255], 8) ^ this.workingKeys[indexKey][1];
		this.C2 = T0[calcBlock[2] & 255] ^ shift(T0[(calcBlock[3] >> 8) & 255], 24) ^ shift(T0[(calcBlock[0] >> 16) & 255], 16)
				^ shift(T0[(calcBlock[1] >> 24) & 255], 8) ^ this.workingKeys[indexKey][2];
		this.C3 = T0[calcBlock[3] & 255] ^ shift(T0[(calcBlock[0] >> 8) & 255], 24) ^ shift(T0[(calcBlock[1] >> 16) & 255], 16)
				^ shift(T0[(calcBlock[2] >> 24) & 255], 8) ^ this.workingKeys[indexKey][3];
	}

	private void stateOut(byte[] bytes) {
		int index = 0;

		bytes[index++] = (byte) this.C0;
		bytes[index++] = (byte) (this.C0 >> 8);
		bytes[index++] = (byte) (this.C0 >> 16);
		bytes[index++] = (byte) (this.C0 >> 24);

		bytes[index++] = (byte) this.C1;
		bytes[index++] = (byte) (this.C1 >> 8);
		bytes[index++] = (byte) (this.C1 >> 16);
		bytes[index++] = (byte) (this.C1 >> 24);

		bytes[index++] = (byte) this.C2;
		bytes[index++] = (byte) (this.C2 >> 8);
		bytes[index++] = (byte) (this.C2 >> 16);
		bytes[index++] = (byte) (this.C2 >> 24);

		bytes[index++] = (byte) this.C3;
		bytes[index++] = (byte) (this.C3 >> 8);
		bytes[index++] = (byte) (this.C3 >> 16);
		bytes[index] = (byte) (this.C3 >> 24);
	}

	private void generateWorkingKeys(byte[] keys) throws ZipException {
		int kc = keys.length / 4;
		if (((kc != 4) && (kc != 6) && (kc != 8)) || ((kc * 4) != keys.length)) {
			throw new ZipException(0x0000001B0004L, "Invalid_Key_Length_AES_Zip_Error");
		}

		this.rounds = kc + 6;
		this.workingKeys = new int[this.rounds + 1][4];

		int t = 0, i = 0;

		while (i < keys.length) {
			this.workingKeys[t >> 2][t & 3] = (keys[i] & 0xFF) | ((keys[i + 1] & 0xFF) << 8) | ((keys[i + 2] & 0xFF) << 16) | (keys[i + 3] << 24);
			i += 4;
			t++;
		}

		int k = (this.rounds + 1) << 2;
		for (i = kc; i < k; i++) {
			int temp = this.workingKeys[(i - 1) >> 2][(i - 1) & 3];
			if ((i % kc) == 0) {
				temp = this.subWord(this.shift(temp, 8)) ^ R_CON[(i / kc) - 1];
			} else if ((kc > 6) && ((i % kc) == 4)) {
				temp = this.subWord(temp);
			}

			this.workingKeys[i >> 2][i & 3] = this.workingKeys[(i - kc) >> 2][(i - kc) & 3] ^ temp;
		}
	}

	private int shift(int r, int shift) {
		return (r >>> shift) | (r << -shift);
	}

	private int subWord(int value) {
		return (SUB_WORD_TABLE[value & 255] & 255 | ((SUB_WORD_TABLE[(value >> 8) & 255] & 255) << 8)
				| ((SUB_WORD_TABLE[(value >> 16) & 255] & 255) << 16) | SUB_WORD_TABLE[(value >> 24) & 255] << 24);
	}

	private static final byte[] SUB_WORD_TABLE = {
			(byte) 99, (byte) 124, (byte) 119, (byte) 123, (byte) 242, (byte) 107, (byte) 111, (byte) 197,
			(byte) 48, (byte) 1, (byte) 103, (byte) 43, (byte) 254, (byte) 215, (byte) 171, (byte) 118,
			(byte) 202, (byte) 130, (byte) 201, (byte) 125, (byte) 250, (byte) 89, (byte) 71, (byte) 240,
			(byte) 173, (byte) 212, (byte) 162, (byte) 175, (byte) 156, (byte) 164, (byte) 114, (byte) 192,
			(byte) 183, (byte) 253, (byte) 147, (byte) 38, (byte) 54, (byte) 63, (byte) 247, (byte) 204,
			(byte) 52, (byte) 165, (byte) 229, (byte) 241, (byte) 113, (byte) 216, (byte) 49, (byte) 21,
			(byte) 4, (byte) 199, (byte) 35, (byte) 195, (byte) 24, (byte) 150, (byte) 5, (byte) 154,
			(byte) 7, (byte) 18, (byte) 128, (byte) 226, (byte) 235, (byte) 39, (byte) 178, (byte) 117,
			(byte) 9, (byte) 131, (byte) 44, (byte) 26, (byte) 27, (byte) 110, (byte) 90, (byte) 160,
			(byte) 82, (byte) 59, (byte) 214, (byte) 179, (byte) 41, (byte) 227, (byte) 47, (byte) 132,
			(byte) 83, (byte) 209, (byte) 0, (byte) 237, (byte) 32, (byte) 252, (byte) 177, (byte) 91,
			(byte) 106, (byte) 203, (byte) 190, (byte) 57, (byte) 74, (byte) 76, (byte) 88, (byte) 207,
			(byte) 208, (byte) 239, (byte) 170, (byte) 251, (byte) 67, (byte) 77, (byte) 51, (byte) 133,
			(byte) 69, (byte) 249, (byte) 2, (byte) 127, (byte) 80, (byte) 60, (byte) 159, (byte) 168,
			(byte) 81, (byte) 163, (byte) 64, (byte) 143, (byte) 146, (byte) 157, (byte) 56, (byte) 245,
			(byte) 188, (byte) 182, (byte) 218, (byte) 33, (byte) 16, (byte) 255, (byte) 243, (byte) 210,
			(byte) 205, (byte) 12, (byte) 19, (byte) 236, (byte) 95, (byte) 151, (byte) 68, (byte) 23,
			(byte) 196, (byte) 167, (byte) 126, (byte) 61, (byte) 100, (byte) 93, (byte) 25, (byte) 115,
			(byte) 96, (byte) 129, (byte) 79, (byte) 220, (byte) 34, (byte) 42, (byte) 144, (byte) 136,
			(byte) 70, (byte) 238, (byte) 184, (byte) 20, (byte) 222, (byte) 94, (byte) 11, (byte) 219,
			(byte) 224, (byte) 50, (byte) 58, (byte) 10, (byte) 73, (byte) 6, (byte) 36, (byte) 92,
			(byte) 194, (byte) 211, (byte) 172, (byte) 98, (byte) 145, (byte) 149, (byte) 228, (byte) 121,
			(byte) 231, (byte) 200, (byte) 55, (byte) 109, (byte) 141, (byte) 213, (byte) 78, (byte) 169,
			(byte) 108, (byte) 86, (byte) 244, (byte) 234, (byte) 101, (byte) 122, (byte) 174, (byte) 8,
			(byte) 186, (byte) 120, (byte) 37, (byte) 46, (byte) 28, (byte) 166, (byte) 180, (byte) 198,
			(byte) 232, (byte) 221, (byte) 116, (byte) 31, (byte) 75, (byte) 189, (byte) 139, (byte) 138,
			(byte) 112, (byte) 62, (byte) 181, (byte) 102, (byte) 72, (byte) 3, (byte) 246, (byte) 14,
			(byte) 97, (byte) 53, (byte) 87, (byte) 185, (byte) 134, (byte) 193, (byte) 29, (byte) 158,
			(byte) 225, (byte) 248, (byte) 152, (byte) 17, (byte) 105, (byte) 217, (byte) 142, (byte) 148,
			(byte) 155, (byte) 30, (byte) 135, (byte) 233, (byte) 206, (byte) 85, (byte) 40, (byte) 223,
			(byte) 140, (byte) 161, (byte) 137, (byte) 13, (byte) 191, (byte) 230, (byte) 66, (byte) 104,
			(byte) 65, (byte) 153, (byte) 45, (byte) 15, (byte) 176, (byte) 84, (byte) 187, (byte) 22,
	};

	private static final int[] R_CON = {
			0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
			0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
	};

	private static final int[] T0 = {
			0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6, 0x0df2f2ff, 0xbd6b6bd6, 0xb16f6fde, 0x54c5c591,
			0x50303060, 0x03010102, 0xa96767ce, 0x7d2b2b56, 0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 0x9a7676ec,
			0x45caca8f, 0x9d82821f, 0x40c9c989, 0x877d7dfa, 0x15fafaef, 0xeb5959b2, 0xc947478e, 0x0bf0f0fb,
			0xecadad41, 0x67d4d4b3, 0xfda2a25f, 0xeaafaf45, 0xbf9c9c23, 0xf7a4a453, 0x967272e4, 0x5bc0c09b,
			0xc2b7b775, 0x1cfdfde1, 0xae93933d, 0x6a26264c, 0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83,
			0x5c343468, 0xf4a5a551, 0x34e5e5d1, 0x08f1f1f9, 0x937171e2, 0x73d8d8ab, 0x53313162, 0x3f15152a,
			0x0c040408, 0x52c7c795, 0x65232346, 0x5ec3c39d, 0x28181830, 0xa1969637, 0x0f05050a, 0xb59a9a2f,
			0x0907070e, 0x36121224, 0x9b80801b, 0x3de2e2df, 0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea,
			0x1b090912, 0x9e83831d, 0x742c2c58, 0x2e1a1a34, 0x2d1b1b36, 0xb26e6edc, 0xee5a5ab4, 0xfba0a05b,
			0xf65252a4, 0x4d3b3b76, 0x61d6d6b7, 0xceb3b37d, 0x7b292952, 0x3ee3e3dd, 0x712f2f5e, 0x97848413,
			0xf55353a6, 0x68d1d1b9, 0x00000000, 0x2cededc1, 0x60202040, 0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6,
			0xbe6a6ad4, 0x46cbcb8d, 0xd9bebe67, 0x4b393972, 0xde4a4a94, 0xd44c4c98, 0xe85858b0, 0x4acfcf85,
			0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed, 0xc5434386, 0xd74d4d9a, 0x55333366, 0x94858511,
			0xcf45458a, 0x10f9f9e9, 0x06020204, 0x817f7ffe, 0xf05050a0, 0x443c3c78, 0xba9f9f25, 0xe3a8a84b,
			0xf35151a2, 0xfea3a35d, 0xc0404080, 0x8a8f8f05, 0xad92923f, 0xbc9d9d21, 0x48383870, 0x04f5f5f1,
			0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142, 0x30101020, 0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf,
			0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3, 0xe15f5fbe, 0xa2979735, 0xcc444488, 0x3917172e,
			0x57c4c493, 0xf2a7a755, 0x827e7efc, 0x473d3d7a, 0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6,
			0xa06060c0, 0x98818119, 0xd14f4f9e, 0x7fdcdca3, 0x66222244, 0x7e2a2a54, 0xab90903b, 0x8388880b,
			0xca46468c, 0x29eeeec7, 0xd3b8b86b, 0x3c141428, 0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad,
			0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14, 0xdb494992, 0x0a06060c, 0x6c242448, 0xe45c5cb8,
			0x5dc2c29f, 0x6ed3d3bd, 0xefacac43, 0xa66262c4, 0xa8919139, 0xa4959531, 0x37e4e4d3, 0x8b7979f2,
			0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda, 0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949,
			0xb46c6cd8, 0xfa5656ac, 0x07f4f4f3, 0x25eaeacf, 0xaf6565ca, 0x8e7a7af4, 0xe9aeae47, 0x18080810,
			0xd5baba6f, 0x887878f0, 0x6f25254a, 0x722e2e5c, 0x241c1c38, 0xf1a6a657, 0xc7b4b473, 0x51c6c697,
			0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e, 0xdd4b4b96, 0xdcbdbd61, 0x868b8b0d, 0x858a8a0f,
			0x907070e0, 0x423e3e7c, 0xc4b5b571, 0xaa6666cc, 0xd8484890, 0x05030306, 0x01f6f6f7, 0x120e0e1c,
			0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969, 0x91868617, 0x58c1c199, 0x271d1d3a, 0xb99e9e27,
			0x38e1e1d9, 0x13f8f8eb, 0xb398982b, 0x33111122, 0xbb6969d2, 0x70d9d9a9, 0x898e8e07, 0xa7949433,
			0xb69b9b2d, 0x221e1e3c, 0x92878715, 0x20e9e9c9, 0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5,
			0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a, 0xdabfbf65, 0x31e6e6d7, 0xc6424284, 0xb86868d0,
			0xc3414182, 0xb0999929, 0x772d2d5a, 0x110f0f1e, 0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d, 0x3a16162c
	};
}
