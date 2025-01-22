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
package org.nervousync.security.crypto;

import org.nervousync.commons.Globals;
import org.nervousync.security.crypto.config.CipherConfig;
import org.nervousync.enumerations.crypto.CryptoMode;
import org.nervousync.exceptions.crypto.CryptoException;
import org.nervousync.utils.SecurityUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;

/**
 * <h2 class="en-US">Abstract asymmetric crypto adapter class</h2>
 * <h2 class="zh-CN">非对称加密解密适配器的抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2012 12:27:33 $
 */
public abstract class AsymmetricCryptoAdapter extends BaseCryptoAdapter {
	/**
	 * <span class="en-US">Asymmetric crypto key instance</span>
	 * <span class="zh-CN">非对称算法密钥实例对象</span>
	 */
	private final Key key;
	/**
	 * <span class="en-US">Cipher block length</span>
	 * <span class="zh-CN">加密块长度</span>
	 */
	private final int blockLength;
	/**
	 * <span class="en-US">Cipher block size</span>
	 * <span class="zh-CN">块数据大小</span>
	 */
	private final int blockSize;
	/**
	 * <span class="en-US">Data append buffer</span>
	 * <span class="zh-CN">数据填充缓冲器</span>
	 */
	private byte[] appendBuffer;
	/**
	 * <span class="en-US">Result data bytes</span>
	 * <span class="zh-CN">结果数据二进制数组</span>
	 */
	private byte[] dataBytes;
	/**
	 * <span class="en-US">Signature instance</span>
	 * <span class="zh-CN">签名实例对象</span>
	 */
	protected Signature signature;

	/**
	 * <h3 class="en-US">Constructor for AsymmetricCryptoAdapter</h3>
	 * <h3 class="zh-CN">非对称加密解密适配器的抽象类的构造方法</h3>
	 *
	 * @param cipherConfig <span class="en-US">Cipher configure</span>
	 *                     <span class="zh-CN">密码设置</span>
	 * @param cryptoMode   <span class="en-US">Crypto mode</span>
	 *                     <span class="zh-CN">加密解密模式</span>
	 * @param cipherKey    <span class="en-US">Crypto key</span>
	 *                     <span class="zh-CN">加密解密密钥</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when initialize cipher</span>
	 *                         <span class="zh-CN">当初始化加密解密实例对象时出现异常</span>
	 */
	protected AsymmetricCryptoAdapter(final CipherConfig cipherConfig, final CryptoMode cryptoMode,
	                                  final CipherKey cipherKey, final int paddingLength) throws CryptoException {
		super(cipherConfig, cryptoMode, cipherKey);
		this.key = cipherKey.getKey();
		this.blockLength = SecurityUtils.rsaKeySize(this.key) >> 3;
		if (paddingLength > 0) {
			this.blockSize = this.blockLength - paddingLength;
		} else {
			this.blockSize = this.blockLength;
		}
		this.appendBuffer = new byte[0];
		this.dataBytes = new byte[0];
		this.reset();
	}

	/**
	 * <h3 class="en-US">Append parts of the given binary data array to current adapter</h3>
	 * <h3 class="zh-CN">追加给定的二进制字节数组到当前适配器</h3>
	 *
	 * @param dataBytes <span class="en-US">binary data array</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Data begin position</span>
	 *                  <span class="zh-CN">数据起始坐标</span>
	 * @param length    <span class="en-US">Length of data append</span>
	 *                  <span class="zh-CN">追加的数据长度</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when process data</span>
	 *                         <span class="zh-CN">当处理数据时出现异常</span>
	 */
	@Override
	public final void append(final byte[] dataBytes, final int position, final int length) throws CryptoException {
		if (dataBytes.length < (position + length)) {
			throw new CryptoException(0x000000150001L, "Length_Not_Enough_Crypto_Error");
		}
		switch (this.cryptoMode) {
			case ENCRYPT:
			case DECRYPT:
				this.appendBuffer(dataBytes, position, length);
				this.process();
				break;
			case SIGNATURE:
			case VERIFY:
				try {
					this.signature.update(dataBytes);
				} catch (SignatureException e) {
					throw new CryptoException(0x000000150002L, "Append_Data_Crypto_Error", e);
				}
				break;
			default:
				throw new CryptoException(0x000000150003L, "Mode_Invalid_Crypto_Error");
		}
	}

	/**
	 * <h3 class="en-US">Append parts of the given binary data array to data append buffer</h3>
	 * <h3 class="zh-CN">追加给定的二进制字节数组到当前数据追加缓冲器中</h3>
	 *
	 * @param dataBytes <span class="en-US">binary data array</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Data begin position</span>
	 *                  <span class="zh-CN">数据起始坐标</span>
	 * @param length    <span class="en-US">Length of data append</span>
	 *                  <span class="zh-CN">追加的数据长度</span>
	 */
	private void appendBuffer(final byte[] dataBytes, final int position, final int length) {
		this.appendBuffer = ByteBuffer.allocate(this.appendBuffer.length + length)
				.put(this.appendBuffer)
				.put(dataBytes, position, length)
				.array();
	}

	/**
	 * <h3 class="en-US">Process append buffer data</h3>
	 * <h3 class="zh-CN">处理追加缓冲区中的数据</h3>
	 *
	 * @throws CryptoException <span class="en-US">If an error occurs when process data</span>
	 *                         <span class="zh-CN">当处理数据时出现异常</span>
	 */
	private void process() throws CryptoException {
		int blockLength = CryptoMode.ENCRYPT.equals(this.cryptoMode) ? this.blockSize : this.blockLength;
		if (blockLength == Globals.DEFAULT_VALUE_INT || this.appendBuffer.length < blockLength) {
			return;
		}
		int position = 0;
		while (position + blockLength < this.appendBuffer.length) {
			byte[] dataBytes = new byte[blockLength];
			System.arraycopy(this.appendBuffer, position, dataBytes, Globals.INITIALIZE_INT_VALUE, blockLength);
			try {
				byte[] encBytes = this.cipher.doFinal(dataBytes);
				this.dataBytes = concat(this.dataBytes, encBytes);
			} catch (IllegalBlockSizeException | BadPaddingException e) {
				throw new CryptoException(0x000000150004L, "Process_Data_Crypto_Error", e);
			} finally {
				this.reset();
			}
			position += blockLength;
		}
		int remainLength = this.appendBuffer.length - position;
		this.appendBuffer = ByteBuffer.allocate(remainLength).put(this.appendBuffer, position, remainLength).array();
	}

	/**
	 * <h3 class="en-US">Concat binary data arrays</h3>
	 * <h3 class="zh-CN">处理追加缓冲区中的数据</h3>
	 *
	 * @param dataBytes   <span class="en-US">Original data bytes</span>
	 *                    <span class="zh-CN">原有字节数组</span>
	 * @param concatBytes <span class="en-US">Concat data bytes</span>
	 *                    <span class="zh-CN">合并连接的字节数组</span>
	 * @return <span class="en-US">Concat data bytes</span>
	 * <span class="zh-CN">合并连接后的字节数组</span>
	 */
	private static byte[] concat(final byte[] dataBytes, final byte[] concatBytes) {
		if (dataBytes == null || dataBytes.length == 0) {
			return concatBytes;
		}

		if (concatBytes == null || concatBytes.length == 0) {
			return dataBytes;
		}
		byte[] newBytes = Arrays.copyOf(dataBytes, dataBytes.length + concatBytes.length);
		System.arraycopy(concatBytes, Globals.INITIALIZE_INT_VALUE, newBytes, dataBytes.length, concatBytes.length);
		return newBytes;
	}

	/**
	 * <h3 class="en-US">Append parts of the given binary data array to current adapter and calculate final result</h3>
	 * <h3 class="zh-CN">追加给定的二进制字节数组到当前适配器并计算最终结果</h3>
	 *
	 * @param dataBytes <span class="en-US">binary data array</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Data begin position</span>
	 *                  <span class="zh-CN">数据起始坐标</span>
	 * @param length    <span class="en-US">Length of data append</span>
	 *                  <span class="zh-CN">追加的数据长度</span>
	 * @return <span class="en-US">Calculate result data byte array</span>
	 * <span class="zh-CN">计算的二进制字节数组结果</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when process data</span>
	 *                         <span class="zh-CN">当处理数据时出现异常</span>
	 */
	@Override
	public final byte[] finish(final byte[] dataBytes, final int position, final int length) throws CryptoException {
		byte[] result;
		switch (this.cryptoMode) {
			case ENCRYPT:
			case DECRYPT:
				this.appendBuffer(dataBytes, position, length);
				this.process();
				if (this.appendBuffer.length > 0) {
					byte[] finalBytes = new byte[this.appendBuffer.length];
					System.arraycopy(this.appendBuffer, Globals.INITIALIZE_INT_VALUE, finalBytes,
							Globals.INITIALIZE_INT_VALUE, this.appendBuffer.length);
					try {
						byte[] encBytes = this.cipher.doFinal(finalBytes);
						result = concat(this.dataBytes, encBytes);
					} catch (IllegalBlockSizeException | BadPaddingException e) {
						throw new CryptoException(0x000000150004L, "Process_Data_Crypto_Error", e);
					} finally {
						this.reset();
						this.appendBuffer = new byte[0];
					}
				} else {
					result = this.dataBytes;
				}
				this.dataBytes = new byte[0];
				break;
			case SIGNATURE:
				try {
					this.signature.update(dataBytes);
					result = this.signature.sign();
				} catch (SignatureException e) {
					throw new CryptoException(0x000000150005L, "Signature_Data_Crypto_Error", e);
				} finally {
					this.reset();
				}
				break;
			case VERIFY:
				throw new CryptoException(0x000000150006L, "Finish_Verify_Crypto_Error");
			default:
				throw new CryptoException(0x000000150003L, "Mode_Invalid_Crypto_Error");
		}
		return result;
	}

	/**
	 * <h3 class="en-US">Verify given signature data bytes is valid</h3>
	 * <h3 class="zh-CN">验证给定的签名二进制数据是合法的</h3>
	 *
	 * @param signature <span class="en-US">signature data bytes</span>
	 *                  <span class="zh-CN">签名二进制数据</span>
	 * @return <span class="en-US">Verify result</span>
	 * <span class="zh-CN">验证结果</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when process data</span>
	 *                         <span class="zh-CN">当处理数据时出现异常</span>
	 */
	@Override
	public final boolean verify(final byte[] signature) throws CryptoException {
		if (!CryptoMode.VERIFY.equals(this.cryptoMode)) {
			throw new CryptoException(0x000000150007L, "Verify_Method_Crypto_Error");
		}
		try {
			boolean result = this.signature.verify(signature);
			this.reset();
			return result;
		} catch (SignatureException e) {
			throw new CryptoException(0x000000150008L, "Verify_Signature_Crypto_Error", e);
		}
	}

	/**
	 * <h3 class="en-US">Reset current adapter</h3>
	 * <h3 class="zh-CN">重置当前适配器</h3>
	 *
	 * @throws CryptoException <span class="en-US">If an error occurs when process data</span>
	 *                         <span class="zh-CN">当处理数据时出现异常</span>
	 */
	@Override
	public final void reset() throws CryptoException {
		switch (this.cryptoMode) {
			case ENCRYPT:
			case DECRYPT:
				this.cipher = this.initCipher();
				break;
			case SIGNATURE:
			case VERIFY:
				this.signature = this.initSignature();
				break;
			default:
				throw new CryptoException(0x000000150003L, "Mode_Invalid_Crypto_Error");
		}
	}

	/**
	 * <h3 class="en-US">Abstract method for initialize cipher instance</h3>
	 * <h3 class="zh-CN">抽象方法用于初始化加密解密实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized cipher instance</span>
	 * <span class="zh-CN">初始化的加密解密实例对象</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when initialize cipher</span>
	 *                         <span class="zh-CN">当初始化加密解密实例对象时出现异常</span>
	 */
	@Override
	protected Cipher initCipher() throws CryptoException {
		switch (this.cryptoMode) {
			case ENCRYPT:
			case DECRYPT:
				return super.generateCipher(this.key, Globals.INITIALIZE_INT_VALUE);
			default:
				throw new CryptoException(0x000000150003L, "Mode_Invalid_Crypto_Error");
		}
	}

	/**
	 * <h3 class="en-US">Abstract method for initialize signature instance</h3>
	 * <h3 class="zh-CN">抽象方法用于初始化签名实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized signature instance</span>
	 * <span class="zh-CN">初始化的签名实例对象</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when initialize cipher</span>
	 *                         <span class="zh-CN">当初始化加密解密实例对象时出现异常</span>
	 */
	private Signature initSignature() throws CryptoException {
		try {
			Signature signInstance = Signature.getInstance(this.cipherConfig.getAlgorithm());
			switch (this.cryptoMode) {
				case SIGNATURE:
					signInstance.initSign((PrivateKey) this.key);
					break;
				case VERIFY:
					signInstance.initVerify((PublicKey) this.key);
					break;
				default:
					throw new CryptoException(0x000000150003L, "Mode_Invalid_Crypto_Error");
			}
			return signInstance;
		} catch (NoSuchAlgorithmException | InvalidKeyException | ClassCastException e) {
			throw new CryptoException(0x000000150009L, "Init_Signature_Crypto_Error", e);
		}
	}
}
