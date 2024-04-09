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
package org.nervousync.security.digest.config;

/**
 * <h2 class="en-US">CRC configure</h2>
 * <h2 class="zh-CN">CRC设置</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 4, 2018 16:08:46 $
 */
public final class CRCConfig {
	/**
	 * <span class="en-US">CRC bit</span>
	 * <span class="zh-CN">CRC比特位</span>
	 */
	private final int bit;
	/**
	 * <span class="en-US">CRC polynomial</span>
	 * <span class="en-US">CRC多项式编码</span>
	 */
	private final long polynomial;
	/**
	 * <span class="en-US">CRC initialize value</span>
	 * <span class="en-US">CRC初始值</span>
	 */
	private final long init;
	/**
	 * <span class="en-US">CRC XOR out value</span>
	 * <span class="en-US">CRC输出值异或运算</span>
	 */
	private final long xorOut;
	/**
	 * <span class="en-US">CRC output data length</span>
	 * <span class="en-US">CRC输出数据长度</span>
	 */
	private final int outLength;
	/**
	 * <span class="en-US">CRC reverse input data bytes</span>
	 * <span class="en-US">CRC反转输入字节数组</span>
	 */
	private final boolean refIn;
	/**
	 * <span class="en-US">CRC reverse output data bytes</span>
	 * <span class="en-US">CRC反转输出字节数组</span>
	 */
	private final boolean refOut;

	/**
	 * <h3 class="en-US">Constructor method for CRCConfig</h3>
	 * <h3 class="zh-CN">CRC设置的构造方法</h3>
	 *
	 * @param bit        <span class="en-US">CRC bit</span>
	 *                   <span class="zh-CN">CRC比特位</span>
	 * @param polynomial <span class="en-US">CRC polynomial</span>
	 *                   <span class="en-US">CRC多项式编码</span>
	 * @param init       <span class="en-US">CRC initialize value</span>
	 *                   <span class="en-US">CRC初始值</span>
	 * @param xorOut     <span class="en-US">CRC XOR out value</span>
	 *                   <span class="en-US">CRC输出值异或运算</span>
	 * @param refIn      <span class="en-US">CRC reverse input data bytes</span>
	 *                   <span class="en-US">CRC反转输入字节数组</span>
	 * @param refOut     <span class="en-US">CRC reverse output data bytes</span>
	 *                   <span class="en-US">CRC反转输出字节数组</span>
	 */
	public CRCConfig(int bit, long polynomial, long init, long xorOut, boolean refIn, boolean refOut) {
		this.bit = bit;
		this.polynomial = polynomial;
		this.init = init;
		this.xorOut = xorOut;
		this.outLength = (bit % 4 != 0) ? ((bit / 4) + 1) : (bit / 4);
		this.refIn = refIn;
		this.refOut = refOut;
	}

	/**
	 * <h3 class="en-US">Getter method for CRC bit</h3>
	 * <h3 class="zh-CN">CRC比特位的Getter方法</h3>
	 *
	 * @return <span class="en-US">CRC bit</span>
	 * <span class="zh-CN">CRC比特位</span>
	 */
	public int getBit() {
		return bit;
	}

	/**
	 * <h3 class="en-US">Getter method for CRC polynomial</h3>
	 * <h3 class="zh-CN">CRC多项式编码的Getter方法</h3>
	 *
	 * @return <span class="en-US">CRC polynomial</span>
	 * <span class="en-US">CRC多项式编码</span>
	 */
	public long getPolynomial() {
		return polynomial;
	}

	/**
	 * <h3 class="en-US">Getter method for CRC initialize value</h3>
	 * <h3 class="zh-CN">CRC初始值的Getter方法</h3>
	 *
	 * @return <span class="en-US">CRC initialize value</span>
	 * <span class="en-US">CRC初始值</span>
	 */
	public long getInit() {
		return init;
	}

	/**
	 * <h3 class="en-US">Getter method for CRC XOR out value</h3>
	 * <h3 class="zh-CN">CRC输出值异或运算的Getter方法</h3>
	 *
	 * @return <span class="en-US">CRC XOR out value</span>
	 * <span class="en-US">CRC输出值异或运算</span>
	 */
	public long getXorOut() {
		return xorOut;
	}

	/**
	 * <h3 class="en-US">Getter method for CRC output data length</h3>
	 * <h3 class="zh-CN">CRC输出数据长度的Getter方法</h3>
	 *
	 * @return <span class="en-US">CRC output data length</span>
	 * <span class="en-US">CRC输出数据长度</span>
	 */
	public int getOutLength() {
		return outLength;
	}

	/**
	 * <h3 class="en-US">Getter method for CRC reverse input data bytes</h3>
	 * <h3 class="zh-CN">CRC反转输入字节数组的Getter方法</h3>
	 *
	 * @return <span class="en-US">CRC reverse input data bytes</span>
	 * <span class="en-US">CRC反转输入字节数组</span>
	 */
	public boolean isRefIn() {
		return refIn;
	}

	/**
	 * <h3 class="en-US">Getter method for CRC reverse output data bytes</h3>
	 * <h3 class="zh-CN">CRC反转输出字节数组的Getter方法</h3>
	 *
	 * @return <span class="en-US">CRC reverse output data bytes</span>
	 * <span class="en-US">CRC反转输出字节数组</span>
	 */
	public boolean isRefOut() {
		return refOut;
	}
}
