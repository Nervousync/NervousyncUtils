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
package org.nervousync.enumerations.crypto;

/**
 * <h2 class="en-US">Crypto Mode Enumerations</h2>
 * <h2 class="zh-CN">加密模式枚举</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jun 28, 2019 14:32:16 $
 */
public enum CryptoMode {
	/**
	 * <span class="en-US">Encrypt Mode</span>
	 * <span class="zh-CN">加密模式</span>
	 */
	ENCRYPT,
	/**
	 * <span class="en-US">Decrypt Mode</span>
	 * <span class="zh-CN">解密模式</span>
	 */
	DECRYPT,
	/**
	 * <span class="en-US">Signature Mode</span>
	 * <span class="zh-CN">签名模式</span>
	 */
	SIGNATURE,
	/**
	 * <span class="en-US">Verify Signature Mode</span>
	 * <span class="zh-CN">验证签名模式</span>
	 */
	VERIFY
}
