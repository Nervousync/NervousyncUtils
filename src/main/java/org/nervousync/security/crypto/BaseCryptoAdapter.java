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
import org.nervousync.security.api.SecureAdapter;
import org.nervousync.security.crypto.config.CipherConfig;
import org.nervousync.enumerations.crypto.CryptoMode;
import org.nervousync.exceptions.crypto.CryptoException;
import org.nervousync.utils.SecurityUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;

/**
 * <h2 class="en-US">Abstract basic crypto adapter class</h2>
 * <h2 class="zh-CN">加密解密适配器的抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2012 11:30:24 $
 */
public abstract class BaseCryptoAdapter extends SecureAdapter {
	/**
	 * <span class="en-US">Cipher configure</span>
	 * <span class="zh-CN">密码设置</span>
	 */
	protected final CipherConfig cipherConfig;
	/**
	 * <span class="en-US">Crypto mode</span>
	 * <span class="zh-CN">加密解密模式</span>
	 */
	protected final CryptoMode cryptoMode;
	/**
	 * <span class="en-US">Crypto key</span>
	 * <span class="zh-CN">加密解密密钥</span>
	 */
	protected final CipherKey cipherKey;
	/**
	 * <span class="en-US">Cipher instance</span>
	 * <span class="zh-CN">加密解密实例对象</span>
	 * The Cipher.
	 */
	protected Cipher cipher;

	/**
	 * <h3 class="en-US">Constructor for BaseCryptoAdapter</h3>
	 * <h3 class="zh-CN">加密解密适配器的构造方法</h3>
	 *
	 * @param cipherConfig <span class="en-US">Cipher configure</span>
	 *                     <span class="zh-CN">密码设置</span>
	 * @param cryptoMode   <span class="en-US">Crypto mode</span>
	 *                     <span class="zh-CN">加密解密模式</span>
	 * @param cipherKey    <span class="en-US">Crypto key</span>
	 *                     <span class="zh-CN">加密解密密钥</span>
	 */
	protected BaseCryptoAdapter(final CipherConfig cipherConfig, final CryptoMode cryptoMode,
	                            final CipherKey cipherKey) {
		this.cipherConfig = cipherConfig;
		this.cryptoMode = cryptoMode;
		this.cipherKey = cipherKey;
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
	protected abstract Cipher initCipher() throws CryptoException;

	/**
	 * <h3 class="en-US">Generate cipher instance using given parameters</h3>
	 * <h3 class="zh-CN">根据给定的参数信息初始化加密解密实例对象</h3>
	 *
	 * @param key      <span class="en-US">Crypto key</span>
	 *                 <span class="zh-CN">加密解密密钥</span>
	 * @param ivLength <span class="en-US">Length of IV data array</span>
	 *                 <span class="zh-CN">向量二进制数据的长度</span>
	 * @return <span class="en-US">Generated cipher instance</span>
	 * <span class="zh-CN">生成的加密解密密钥</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when generate cipher</span>
	 *                         <span class="zh-CN">当生成的加密解密密钥时出现异常</span>
	 */
	protected final Cipher generateCipher(final Key key, final int ivLength) throws CryptoException {
		IvParameterSpec ivParameterSpec = null;
		if (ivLength > 0) {
			byte[] ivContent = new byte[ivLength];
			System.arraycopy(SecurityUtils.SHA256(this.cipherKey.getKeyBytes()),
					Globals.INITIALIZE_INT_VALUE, ivContent, Globals.INITIALIZE_INT_VALUE, ivContent.length);
			ivParameterSpec = new IvParameterSpec(ivContent);
		}
		try {
			Cipher cipherInstance = Cipher.getInstance(this.cipherConfig.toString(), "BC");
			switch (this.cryptoMode) {
				case ENCRYPT:
					cipherInstance.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
					break;
				case DECRYPT:
					cipherInstance.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
					break;
				default:
					throw new CryptoException(0x000000150009L, "Mode_Invalid_Crypto_Error");
			}
			return cipherInstance;
		} catch (Exception e) {
			if (e instanceof CryptoException) {
				throw (CryptoException) e;
			}
			throw new CryptoException(0x00000015000BL, "Init_Cipher_Crypto_Error", e);
		}
	}

	/**
	 * <h2 class="en-US">Cipher key define</h2>
	 * <h2 class="zh-CN">加密解密密钥定义</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2012 11:32:08 $
	 */
	public static final class CipherKey {
		/**
		 * <span class="en-US">Key size</span>
		 * <span class="zh-CN">密钥长度</span>
		 */
		private final int keySize;
		/**
		 * <span class="en-US">Key data bytes</span>
		 * <span class="zh-CN">密钥字节数组</span>
		 */
		private final byte[] keyBytes;
		/**
		 * <span class="en-US">Random algorithm</span>
		 * <span class="zh-CN">随机数算法</span>
		 */
		private final String randomAlgorithm;
		/**
		 * <span class="en-US">Asymmetric crypto key instance</span>
		 * <span class="zh-CN">非对称算法密钥实例对象</span>
		 */
		private final Key key;

		/**
		 * <h3 class="en-US">Constructor for CipherKey</h3>
		 * <h3 class="zh-CN">加密解密密钥定义的构造方法</h3>
		 *
		 * @param keyBytes <span class="en-US">Key data bytes</span>
		 *                 <span class="zh-CN">密钥字节数组</span>
		 */
		public CipherKey(final byte[] keyBytes) {
			this(Globals.DEFAULT_VALUE_INT, keyBytes, Globals.DEFAULT_VALUE_STRING, null);
		}

		/**
		 * <h3 class="en-US">Constructor for CipherKey</h3>
		 * <h3 class="zh-CN">加密解密密钥定义的构造方法</h3>
		 *
		 * @param keySize         <span class="en-US">Key size</span>
		 *                        <span class="zh-CN">密钥长度</span>
		 * @param keyBytes        <span class="en-US">Key data bytes</span>
		 *                        <span class="zh-CN">密钥字节数组</span>
		 * @param randomAlgorithm <span class="en-US">Random algorithm</span>
		 *                        <span class="zh-CN">随机数算法</span>
		 */
		public CipherKey(final int keySize, final byte[] keyBytes, final String randomAlgorithm) {
			this(keySize, keyBytes, randomAlgorithm, null);
		}

		/**
		 * <h3 class="en-US">Constructor for CipherKey</h3>
		 * <h3 class="zh-CN">加密解密密钥定义的构造方法</h3>
		 *
		 * @param key <span class="en-US">Asymmetric crypto key instance</span>
		 *            <span class="zh-CN">非对称算法密钥实例对象</span>
		 */
		public CipherKey(final Key key) {
			this(Globals.DEFAULT_VALUE_INT, new byte[0], Globals.DEFAULT_VALUE_STRING, key);
		}

		/**
		 * <h3 class="en-US">Constructor for CipherKey</h3>
		 * <h3 class="zh-CN">加密解密密钥定义的构造方法</h3>
		 *
		 * @param keySize         <span class="en-US">Key size</span>
		 *                        <span class="zh-CN">密钥长度</span>
		 * @param keyBytes        <span class="en-US">Key data bytes</span>
		 *                        <span class="zh-CN">密钥字节数组</span>
		 * @param randomAlgorithm <span class="en-US">Random algorithm</span>
		 *                        <span class="zh-CN">随机数算法</span>
		 * @param key             <span class="en-US">Asymmetric crypto key instance</span>
		 *                        <span class="zh-CN">非对称算法密钥实例对象</span>
		 */
		private CipherKey(final int keySize, final byte[] keyBytes, final String randomAlgorithm, final Key key) {
			this.keySize = keySize;
			this.keyBytes = keyBytes;
			this.randomAlgorithm = randomAlgorithm;
			this.key = key;
		}

		/**
		 * <h3 class="en-US">Getter method for Key size</h3>
		 * <h3 class="zh-CN">密钥长度的Getter方法</h3>
		 *
		 * @return <span class="en-US">Key size</span>
		 * <span class="zh-CN">密钥长度</span>
		 */
		public int getKeySize() {
			return keySize;
		}

		/**
		 * <h3 class="en-US">Getter method for Key data bytes</h3>
		 * <h3 class="zh-CN">密钥字节数组的Getter方法</h3>
		 *
		 * @return <span class="en-US">Key data bytes</span>
		 * <span class="zh-CN">密钥字节数组</span>
		 */
		public byte[] getKeyBytes() {
			return keyBytes;
		}

		/**
		 * <h3 class="en-US">Getter method for Random algorithm</h3>
		 * <h3 class="zh-CN">随机数算法的Getter方法</h3>
		 *
		 * @return <span class="en-US">Random algorithm</span>
		 * <span class="zh-CN">随机数算法</span>
		 */
		public String getRandomAlgorithm() {
			return randomAlgorithm;
		}

		/**
		 * <h3 class="en-US">Getter method for Asymmetric crypto key instance</h3>
		 * <h3 class="zh-CN">非对称算法密钥实例对象的Getter方法</h3>
		 *
		 * @return <span class="en-US">Asymmetric crypto key instance</span>
		 * <span class="zh-CN">非对称算法密钥实例对象</span>
		 */
		public Key getKey() {
			return key;
		}
	}
}
