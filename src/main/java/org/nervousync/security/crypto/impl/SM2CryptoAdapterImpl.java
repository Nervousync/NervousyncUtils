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
package org.nervousync.security.crypto.impl;

import org.nervousync.commons.Globals;
import org.nervousync.enumerations.crypto.CryptoMode;
import org.nervousync.exceptions.crypto.CryptoException;
import org.nervousync.security.crypto.AsymmetricCryptoAdapter;
import org.nervousync.security.crypto.config.CipherConfig;

/**
 * <h2 class="en-US">Asymmetric SM2 crypto adapter class</h2>
 * <h2 class="zh-CN">SM2非对称加密解密适配器的实现类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2012 14:33:28 $
 */
public final class SM2CryptoAdapterImpl extends AsymmetricCryptoAdapter {

	/**
	 * <h3 class="en-US">Constructor for SM2CryptoAdapterImpl</h3>
	 * <h3 class="zh-CN">SM2非对称加密解密适配器的实现类的构造方法</h3>
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
	public SM2CryptoAdapterImpl(final CipherConfig cipherConfig, final CryptoMode cryptoMode,
	                            final CipherKey cipherKey) throws CryptoException {
		super(cipherConfig, cryptoMode, cipherKey, Globals.INITIALIZE_INT_VALUE);
	}
}
