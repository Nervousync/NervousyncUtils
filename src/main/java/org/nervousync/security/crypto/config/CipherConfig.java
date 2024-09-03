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
package org.nervousync.security.crypto.config;

import java.io.Serializable;

/**
 * <h2 class="en-US">Cipher configure</h2>
 * <h2 class="zh-CN">密码设置</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2016 15:47:22 $
 */
public final class CipherConfig implements Serializable {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = -2132901674474697239L;
	/**
	 * <span class="en-US">Cipher Algorithm</span>
	 * <span class="zh-CN">密码算法</span>
	 */
	private final String algorithm;
	/**
	 * <span class="en-US">Cipher Mode</span>
	 * <span class="zh-CN">分组密码模式</span>
	 * Cipher Mode
	 */
	private final String mode;
	/**
	 * <span class="en-US">Padding Mode</span>
	 * <span class="zh-CN">数据填充模式</span>
	 */
	private final String padding;

	/**
	 * <h3 class="en-US">Constructor method for CipherConfig</h3>
	 * <h3 class="zh-CN">密码设置的构造方法</h3>
	 *
	 * @param algorithm <span class="en-US">Cipher Algorithm</span>
	 *                  <span class="zh-CN">密码算法</span>
	 * @param mode      <span class="en-US">Cipher Mode</span>
	 *                  <span class="zh-CN">分组密码模式</span>
	 * @param padding   <span class="en-US">Padding Mode</span>
	 *                  <span class="zh-CN">数据填充模式</span>
	 */
	public CipherConfig(String algorithm, String mode, String padding) {
		this.algorithm = algorithm;
		this.mode = mode;
		this.padding = padding;
	}

	/**
	 * <h3 class="en-US">Getter method for Cipher Algorithm</h3>
	 * <h3 class="zh-CN">密码算法的Getter方法</h3>
	 *
	 * @return <span class="en-US">Cipher Algorithm</span>
	 * <span class="zh-CN">密码算法</span>
	 */
	public String getAlgorithm() {
		return algorithm;
	}

	/**
	 * <h3 class="en-US">Getter method for Cipher Mode</h3>
	 * <h3 class="zh-CN">分组密码模式的Getter方法</h3>
	 *
	 * @return <span class="en-US">Cipher Mode</span>
	 * <span class="zh-CN">分组密码模式</span>
	 */
	public String getMode() {
		return mode;
	}

	/**
	 * <h3 class="en-US">Getter method for Padding Mode</h3>
	 * <h3 class="zh-CN">数据填充模式的Getter方法</h3>
	 *
	 * @return <span class="en-US">Padding Mode</span>
	 * <span class="zh-CN">数据填充模式</span>
	 */
	public String getPadding() {
		return padding;
	}

	/**
	 * <h3 class="en-US">Convert current cipher configure to string</h3>
	 * <h3 class="zh-CN">转换当前密码配置信息为字符串</h3>
	 *
	 * @return <span class="en-US">Converted string</span>
	 * <span class="zh-CN">转换后的字符串</span>
	 */
	@Override
	public String toString() {
		return String.join("/", this.algorithm, this.mode, this.padding);
	}
}
