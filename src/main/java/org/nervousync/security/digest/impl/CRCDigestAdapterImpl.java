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
package org.nervousync.security.digest.impl;

import org.nervousync.exceptions.crypto.CryptoException;
import org.nervousync.exceptions.utils.DataInvalidException;
import org.nervousync.security.api.SecureAdapter;
import org.nervousync.security.digest.config.CRCConfig;
import org.nervousync.utils.RawUtils;

import java.nio.ByteOrder;
import java.util.Objects;

/**
 * <h2 class="en-US">Symmetric CRC crypto adapter class</h2>
 * <h2 class="zh-CN">CRC摘要算法适配器的实现类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2012 13:50:21 $
 */
public final class CRCDigestAdapterImpl extends SecureAdapter {
	/**
	 * <span class="en-US">CRC configure</span>
	 * <span class="zh-CN">CRC设置</span>
	 */
	private final CRCConfig crcConfig;
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
	 * <span class="en-US">CRC check value</span>
	 */
	private final long check;
	/**
	 * <span class="en-US">CRC mask value</span>
	 */
	private final long mask;
	/**
	 * <span class="en-US">CRC result</span>
	 * <span class="en-US">CRC计算结果</span>
	 */
	private long crc;

	/**
	 * <h3 class="en-US">Constructor for CRCDigestAdapterImpl</h3>
	 * <h3 class="zh-CN">CRC摘要算法适配器实现类类的构造方法</h3>
	 *
	 * @param crcConfig <span class="en-US">CRC configure</span>
	 *                  <span class="zh-CN">CRC设置</span>
	 */
	public CRCDigestAdapterImpl(final CRCConfig crcConfig) {
		this.crcConfig = crcConfig;
		if (this.crcConfig.isRefIn()) {
			this.polynomial = reverseBit(this.crcConfig.getPolynomial(), this.crcConfig.getBit());
			this.init = reverseBit(this.crcConfig.getInit(), this.crcConfig.getBit());
		} else {
			this.polynomial = (this.crcConfig.getBit() < 8)
					? (this.crcConfig.getPolynomial() << (8 - this.crcConfig.getBit()))
					: this.crcConfig.getPolynomial();
			this.init = (this.crcConfig.getBit() < 8)
					? (this.crcConfig.getInit() << (8 - this.crcConfig.getBit()))
					: this.crcConfig.getInit();
		}
		this.crc = this.init;
		if (this.crcConfig.isRefIn()) {
			this.check = 0x1L;
		} else {
			if (this.crcConfig.getBit() <= 8) {
				this.check = 0x80;
			} else {
				this.check = Double.valueOf(Math.pow(2, this.crcConfig.getBit() - 1)).longValue();
			}
		}
		if (this.crcConfig.getBit() <= 8) {
			this.mask = 0xFF;
		} else {
			StringBuilder stringBuilder = new StringBuilder();
			while (stringBuilder.length() < this.crcConfig.getBit()) {
				stringBuilder.append("1");
			}
			this.mask = Long.valueOf(stringBuilder.toString(), 2);
		}
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
	@Override
	public void append(final byte[] dataBytes, final int position, final int length) throws CryptoException {
		if (dataBytes.length < (position + length)) {
			throw new CryptoException(0x000000150001L, "Length_Not_Enough_Crypto_Error");
		}
		for (int i = position; i < length; i++) {
			long crc = (dataBytes[i] < 0) ? ((int) dataBytes[i]) + 256 : dataBytes[i];
			if (this.crcConfig.getBit() <= 8) {
				this.crc ^= crc;
			} else {
				this.crc ^= ((this.crcConfig.isRefIn() ? crc : (crc << (this.crcConfig.getBit() - 8))) & this.mask);
			}

			for (int j = 0; j < 8; j++) {
				if ((this.crc & this.check) > 0) {
					this.crc = (this.crcConfig.isRefIn() ? (this.crc >>> 1) : (this.crc << 1)) ^ this.polynomial;
				} else {
					this.crc = this.crcConfig.isRefIn() ? (this.crc >>> 1) : (this.crc << 1);
				}
			}
		}
		this.crc &= this.mask;
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
	public byte[] finish(final byte[] dataBytes, final int position, final int length) throws CryptoException {
		this.append(dataBytes, position, length);
		if (this.crcConfig.getBit() < 8 && !this.crcConfig.isRefIn()) {
			this.crc >>>= (8 - this.crcConfig.getBit());
		}
		if (!Objects.equals(this.crcConfig.isRefIn(), this.crcConfig.isRefOut()) && this.crcConfig.isRefOut()) {
			//  Just using for CRC-12/UMTS
			this.crc &= this.mask;
			this.crc = (reverseBit(this.crc, Long.toString(this.crc, 2).length()) ^ this.crcConfig.getXorOut());
		} else {
			this.crc = (this.crc ^ this.crcConfig.getXorOut()) & this.mask;
		}

		byte[] result = new byte[8];
		try {
			RawUtils.writeLong(result, ByteOrder.LITTLE_ENDIAN, this.crc);
		} catch (DataInvalidException ignore) {
			return new byte[0];
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
	public boolean verify(final byte[] signature) {
		if (signature == null || signature.length != 8) {
			return Boolean.FALSE;
		}
		try {
			return this.crc == RawUtils.readLong(signature, ByteOrder.LITTLE_ENDIAN);
		} catch (DataInvalidException ignore) {
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Reset current adapter</h3>
	 * <h3 class="zh-CN">重置当前适配器</h3>
	 */
	@Override
	public void reset() {
		this.crc = this.init;
	}

	/**
	 * <h3 class="en-US">Reverse result bit</h3>
	 * <h3 class="zh-CN">反转结果比特位</h3>
	 *
	 * @param value <span class="en-US">result value</span>
	 *              <span class="zh-CN">结果值</span>
	 * @param bit   <span class="en-US">Bit value</span>
	 *              <span class="en-US">比特位</span>
	 * @return <span class="en-US">Reverse bit result</span>
	 * <span class="zh-CN">反转比特位的结果值</span>
	 */
	private static long reverseBit(long value, int bit) {
		if (value < 0) {
			value += (long) Math.pow(2, bit);
		}
		String reverseValue = new StringBuilder(Long.toString(value, 2)).reverse().toString();
		if (reverseValue.length() < bit) {
			StringBuilder stringBuilder = new StringBuilder(reverseValue);
			while (stringBuilder.length() < bit) {
				stringBuilder.append("0");
			}
			reverseValue = stringBuilder.toString();
		} else {
			reverseValue = reverseValue.substring(0, bit);
		}
		return Long.parseLong(reverseValue, 2);
	}
}
