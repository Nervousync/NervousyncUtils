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
package org.nervousync.generator.uuid;

import org.nervousync.generator.IGenerator;

/**
 * <h2 class="en-US">Abstract UUID generator</h2>
 * <h2 class="zh-CN">UUID生成器抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 06, 2022 12:48:16 $
 */
public abstract class UUIDGenerator implements IGenerator<String> {
	/**
	 * <h3 class="en-US">Calculate high bits of given data bytes</h3>
	 * <h3 class="zh-CN">从给定的二进制数组计算高位值</h3>
	 *
	 * @param randomBytes <span class="en-US">given data bytes</span>
	 *                    <span class="zh-CN">给定的二进制数组</span>
	 * @return <span class="en-US">High bits value in long</span>
	 * <span class="zh-CN">long型的高位比特值</span>
	 */
	protected final long highBits(byte[] randomBytes) {
		long highBits = 0L;
		for (int i = 0; i < 8; i++) {
			highBits = (highBits << 8) | (randomBytes[i] & 0xFF);
		}
		return highBits;
	}

	/**
	 * <h3 class="en-US">Calculate high bits of given current time milliseconds</h3>
	 * <h3 class="zh-CN">从给定的当前时间戳计算高位值</h3>
	 *
	 * @param currentTimeMillis <span class="en-US">current time milliseconds</span>
	 *                          <span class="zh-CN">当前时间戳</span>
	 * @return <span class="en-US">High bits value in long</span>
	 * <span class="zh-CN">long型的高位比特值</span>
	 */
	protected final long highBits(long currentTimeMillis) {
		return ((currentTimeMillis & 0xFFFFFFFFL) << 32)
				| ((currentTimeMillis & 0xFFFF00000000L) >> 16)
				| 0x1000L
				| ((currentTimeMillis & 0xFFF000000000000L) >> 48);
	}

	/**
	 * <h3 class="en-US">Calculate low bits of given data bytes</h3>
	 * <h3 class="zh-CN">从给定的二进制数组计算低位值</h3>
	 *
	 * @param dataBytes <span class="en-US">given data bytes</span>
	 *                  <span class="zh-CN">给定的二进制数组</span>
	 * @return <span class="en-US">Low bits value in long</span>
	 * <span class="zh-CN">long型的低位比特值</span>
	 */
	protected long lowBits(byte[] dataBytes) {
		long lowBits = 0L;
		for (int index = 8; index < 16; index++) {
			lowBits = (lowBits << 8) | (dataBytes[index] & 0xFF);
		}
		return lowBits;
	}

	/**
	 * <h3 class="en-US">Destroy current generator instance</h3>
	 * <h3 class="zh-CN">销毁当前生成器实例对象</h3>
	 */
	@Override
	public void destroy() {
	}
}
