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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.ByteArrayOutputStream;

/**
 * <h2 class="en-US">Abstract symmetric crypto adapter class</h2>
 * <h2 class="zh-CN">对称加密解密适配器的抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2012 13:16:24 $
 */
public abstract class SymmetricCryptoAdapter extends BaseCryptoAdapter {
	/**
	 * <span class="en-US">Result data bytes output stream</span>
	 * <span class="zh-CN">结果数据二进制数组输出流</span>
	 */
	private ByteArrayOutputStream byteArrayOutputStream;

	/**
	 * <h3 class="en-US">Constructor for SymmetricCryptoAdapter</h3>
	 * <h3 class="zh-CN">对称加密解密适配器的抽象类的构造方法</h3>
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
	protected SymmetricCryptoAdapter(final CipherConfig cipherConfig, final CryptoMode cryptoMode,
	                                 final CipherKey cipherKey) throws CryptoException {
		super(cipherConfig, cryptoMode, cipherKey);
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
				this.byteArrayOutputStream.write(dataBytes, position, length);
				break;
			default:
				throw new CryptoException(0x000000150003L, "Mode_Invalid_Crypto_Error");
		}
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
		switch (this.cryptoMode) {
			case ENCRYPT:
			case DECRYPT:
				try {
					this.byteArrayOutputStream.write(dataBytes, position, length);
					return this.cipher.doFinal(this.byteArrayOutputStream.toByteArray(), Globals.INITIALIZE_INT_VALUE,
							this.byteArrayOutputStream.size());
				} catch (IllegalBlockSizeException | BadPaddingException e) {
					throw new CryptoException(0x000000150004L, "Process_Data_Crypto_Error", e);
				} finally {
					this.reset();
				}
			case SIGNATURE:
			case VERIFY:
				throw new CryptoException(0x00000015000CL, "Not_Support_Mode_Crypto_Error");
			default:
				throw new CryptoException(0x000000150003L, "Mode_Invalid_Crypto_Error");
		}
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
		throw new CryptoException(0x00000015000CL, "Not_Support_Mode_Crypto_Error");
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
				this.byteArrayOutputStream = new ByteArrayOutputStream();
				break;
			default:
				throw new CryptoException(0x000000150003L, "Mode_Invalid_Crypto_Error");
		}
	}
}
