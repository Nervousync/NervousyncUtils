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
package org.nervousync.security.api;

import org.nervousync.exceptions.crypto.CryptoException;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * <h2 class="en-US">Abstract secure adapter class</h2>
 * <h2 class="zh-CN">安全适配器的抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2012 11:23:38 $
 */
public abstract class SecureAdapter {
	/**
	 * <h3 class="en-US">Append given string to current adapter</h3>
	 * <h3 class="zh-CN">追加给定的字符串到当前适配器</h3>
	 *
	 * @param strIn <span class="en-US">Input string</span>
	 *              <span class="zh-CN">输入的字符串</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when process data</span>
	 *                         <span class="zh-CN">当处理数据时出现异常</span>
	 */
	public final void append(String strIn) throws CryptoException {
		this.append(strIn.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * <h3 class="en-US">Append given binary data array to current adapter</h3>
	 * <h3 class="zh-CN">追加给定的二进制字节数组到当前适配器</h3>
	 *
	 * @param dataBytes <span class="en-US">binary data array</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when process data</span>
	 *                         <span class="zh-CN">当处理数据时出现异常</span>
	 */
	public final void append(byte[] dataBytes) throws CryptoException {
		this.append(dataBytes, 0, dataBytes.length);
	}

	/**
	 * <h3 class="en-US">Append given byte buffer data to current adapter</h3>
	 * <h3 class="zh-CN">追加给定的二进制缓冲器中的数据到当前适配器</h3>
	 *
	 * @param inBuffer <span class="en-US">byte buffer instance</span>
	 *                 <span class="zh-CN">二进制缓冲器实例对象</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when process data</span>
	 *                         <span class="zh-CN">当处理数据时出现异常</span>
	 */
	public final void append(ByteBuffer inBuffer) throws CryptoException {
		this.append(inBuffer.array());
	}

	/**
	 * <h3 class="en-US">Calculate final result</h3>
	 * <h3 class="zh-CN">计算最终结果</h3>
	 *
	 * @return <span class="en-US">Calculate result data byte array</span>
	 * <span class="zh-CN">计算的二进制字节数组结果</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when process data</span>
	 *                         <span class="zh-CN">当处理数据时出现异常</span>
	 */
	public final byte[] finish() throws CryptoException {
		return this.finish(new byte[0], 0, 0);
	}

	/**
	 * <h3 class="en-US">Append given string to current adapter and calculate final result</h3>
	 * <h3 class="zh-CN">追加给定的字符串到当前适配器并计算最终结果</h3>
	 *
	 * @param strIn <span class="en-US">Input string</span>
	 *              <span class="zh-CN">输入的字符串</span>
	 * @return <span class="en-US">Calculate result data byte array</span>
	 * <span class="zh-CN">计算的二进制字节数组结果</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when process data</span>
	 *                         <span class="zh-CN">当处理数据时出现异常</span>
	 */
	public final byte[] finish(String strIn) throws CryptoException {
		return this.finish(strIn.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * <h3 class="en-US">Append given binary data array to current adapter and calculate final result</h3>
	 * <h3 class="zh-CN">追加给定的二进制字节数组到当前适配器并计算最终结果</h3>
	 *
	 * @param dataBytes <span class="en-US">binary data array</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @return <span class="en-US">Calculate result data byte array</span>
	 * <span class="zh-CN">计算的二进制字节数组结果</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when process data</span>
	 *                         <span class="zh-CN">当处理数据时出现异常</span>
	 */
	public final byte[] finish(byte[] dataBytes) throws CryptoException {
		return this.finish(dataBytes, 0, dataBytes.length);
	}

	/**
	 * <h3 class="en-US">Append given byte buffer data to current adapter and calculate final result</h3>
	 * <h3 class="zh-CN">追加给定的二进制缓冲器中的数据到当前适配器并计算最终结果</h3>
	 *
	 * @param inBuffer <span class="en-US">byte buffer instance</span>
	 *                 <span class="zh-CN">二进制缓冲器实例对象</span>
	 * @return <span class="en-US">Calculate result data byte array</span>
	 * <span class="zh-CN">计算的二进制字节数组结果</span>
	 * @throws CryptoException <span class="en-US">If an error occurs when process data</span>
	 *                         <span class="zh-CN">当处理数据时出现异常</span>
	 */
	public final byte[] finish(ByteBuffer inBuffer) throws CryptoException {
		return this.finish(inBuffer.array());
	}

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
	public abstract void append(byte[] dataBytes, int position, int length) throws CryptoException;

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
	public abstract byte[] finish(byte[] dataBytes, int position, int length) throws CryptoException;

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
	public abstract boolean verify(byte[] signature) throws CryptoException;

	/**
	 * <h3 class="en-US">Reset current adapter</h3>
	 * <h3 class="zh-CN">重置当前适配器</h3>
	 *
	 * @throws CryptoException <span class="en-US">If an error occurs when process data</span>
	 *                         <span class="zh-CN">当处理数据时出现异常</span>
	 */
	public abstract void reset() throws CryptoException;
}
