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
package org.nervousync.security.digest;

import org.bouncycastle.crypto.Mac;
import org.nervousync.commons.Globals;
import org.nervousync.exceptions.crypto.CryptoException;
import org.nervousync.security.api.SecureAdapter;
import org.nervousync.utils.StringUtils;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * <h2 class="en-US">Abstract basic digest adapter class</h2>
 * <h2 class="zh-CN">摘要算法适配器的抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2012 11:46:55 $
 */
public abstract class BaseDigestAdapter extends SecureAdapter {
	/**
	 * <span class="en-US">Hash-based Message Authentication Code</span>
	 * <span class="zh-CN">基于密钥的消息认证码算法</span>
	 */
	private final boolean macMode;
	/**
	 * <span class="en-US">MessageDigest instance</span>
	 * <span class="zh-CN">消息摘要算法实例对象</span>
	 */
	private final MessageDigest messageDigest;
	/**
	 * <span class="en-US">Message Authentication Code instance</span>
	 * <span class="zh-CN">消息认证码算法实例对象</span>
	 */
	private final Mac hmac;

	/**
	 * <h3 class="en-US">Constructor for BaseDigestAdapter</h3>
	 * <h3 class="zh-CN">消息摘要算法适配器的构造方法</h3>
	 *
	 * @param algorithm <span class="en-US">Cipher Algorithm</span>
	 *                  <span class="zh-CN">密码算法</span>
	 * @param keyBytes  <span class="en-US">Hmac key data bytes</span>
	 *                  <span class="zh-CN">消息认证码算法密钥数据数组</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when initialize adaptor</span>
	 *                         <span class="zh-CN">当初始化适配器时出现异常</span>
	 */
	protected BaseDigestAdapter(final String algorithm, final byte[] keyBytes) throws CryptoException {
		if (StringUtils.isEmpty(algorithm)) {
			throw new CryptoException(0x00000015000DL, "Unknown_Algorithm_Digits_Error");
		}
		this.macMode = algorithm.toUpperCase().contains("HMAC");
		this.messageDigest = this.macMode ? null : this.initDigest(algorithm);
		this.hmac = this.macMode ? this.initHmac(algorithm, keyBytes) : null;
	}

	/**
	 * <h3 class="en-US">Abstract method for initialize MessageDigest instance</h3>
	 * <h3 class="zh-CN">抽象方法用于初始化消息摘要算法适配器实例对象</h3>
	 *
	 * @param algorithm <span class="en-US">Cipher Algorithm</span>
	 *                  <span class="zh-CN">密码算法</span>
	 * @return <span class="en-US">Initialized MessageDigest instance</span>
	 * <span class="zh-CN">初始化的消息摘要算法适配器</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when initialize MessageDigest</span>
	 *                         <span class="zh-CN">当初始化消息摘要算法适配器实例对象时出现异常</span>
	 */
	protected abstract MessageDigest initDigest(final String algorithm) throws CryptoException;

	/**
	 * <h3 class="en-US">Abstract method for initialize Hmac instance</h3>
	 * <h3 class="zh-CN">抽象方法用于初始化消息认证码适配器实例对象</h3>
	 *
	 * @param algorithm <span class="en-US">Cipher Algorithm</span>
	 *                  <span class="zh-CN">密码算法</span>
	 * @param keyBytes  <span class="en-US">Hmac key data bytes</span>
	 *                  <span class="zh-CN">消息认证码算法密钥数据数组</span>
	 * @return <span class="en-US">Initialized Hmac instance</span>
	 * <span class="zh-CN">初始化的消息认证码算法适配器</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when initialize Hmac instance</span>
	 *                         <span class="zh-CN">当初始化消息认证码算法适配器实例对象时出现异常</span>
	 */
	protected abstract Mac initHmac(final String algorithm, final byte[] keyBytes) throws CryptoException;

	/**
	 * <h3 class="en-US">Append parts of given binary data array to current adapter</h3>
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
		if (this.macMode) {
			this.hmac.update(dataBytes, position, length);
		} else {
			this.messageDigest.update(dataBytes, position, length);
		}
	}

	/**
	 * <h3 class="en-US">Append parts of given binary data array to current adapter and calculate final result</h3>
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
		if (dataBytes.length < (position + length)) {
			throw new CryptoException(0x000000150001L, "Length_Not_Enough_Crypto_Error");
		}
		this.append(dataBytes, position, length);
		byte[] result;
		if (this.macMode) {
			result = new byte[this.hmac.getMacSize()];
			this.hmac.doFinal(result, 0);
		} else {
			result = this.messageDigest.digest();
		}
		this.reset();
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
	 */
	@Override
	public final boolean verify(final byte[] signature) {
		byte[] calcResult;
		if (this.macMode) {
			calcResult = new byte[this.hmac.getMacSize()];
			this.hmac.doFinal(calcResult, 0);
		} else {
			calcResult = this.messageDigest.digest();
		}
		boolean result = Arrays.equals(calcResult, signature);
		this.reset();
		return result;
	}

	/**
	 * <h3 class="en-US">Reset current adapter</h3>
	 * <h3 class="zh-CN">重置当前适配器</h3>
	 */
	@Override
	public final void reset() {
		if (this.macMode) {
			this.hmac.reset();
		} else {
			this.messageDigest.reset();
		}
	}

	/**
	 * <h3 class="en-US">Retrieve current mac size</h3>
	 * <h3 class="zh-CN">读取当前消息认证码的长度</h3>
	 *
	 * @return <span class="en-US">Mac size</span>
	 * <span class="zh-CN">消息认证码的长度</span>
	 */
	public final int macLength() {
		return this.macMode ? this.hmac.getMacSize() : Globals.DEFAULT_VALUE_INT;
	}
}
