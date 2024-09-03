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
package org.nervousync.generator.uuid.impl;

import org.nervousync.annotations.provider.Provider;
import org.nervousync.commons.Globals;
import org.nervousync.generator.uuid.UUIDGenerator;
import org.nervousync.utils.IDUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * <h2 class="en-US">UUID version 5 generator</h2>
 * <h2 class="zh-CN">UUID版本5生成器</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 06, 2022 12:59:08 $
 */
@Provider(name = IDUtils.UUIDv5, titleKey = "version5.uuid.id.generator.name")
public final class UUIDv5Generator extends UUIDGenerator {
	/**
	 * <h3 class="en-US">Generate ID value</h3>
	 * <h3 class="zh-CN">生成ID值</h3>
	 *
	 * @return <span class="en-US">Generated value</span>
	 * <span class="zh-CN">生成的ID值</span>
	 */
	@Override
	public String generate() {
		return this.generate(new byte[0]);
	}

	/**
	 * <h3 class="en-US">Generate ID value using given parameter</h3>
	 * <h3 class="zh-CN">使用给定的参数生成ID值</h3>
	 *
	 * @param dataBytes <span class="en-US">Given parameter</span>
	 *                  <span class="zh-CN">给定的参数</span>
	 * @return <span class="en-US">Generated value</span>
	 * <span class="zh-CN">生成的ID值</span>
	 */
	@Override
	public String generate(byte[] dataBytes) {
		try {
			byte[] randomBytes = MessageDigest.getInstance("SHA1").digest(dataBytes);
			randomBytes[6] &= 0x0F;     /* clear version        */
			randomBytes[6] |= 0x50;     /* set to version 5     */
			randomBytes[8] &= 0x3F;     /* clear variant        */
			randomBytes[8] |= (byte) 0x80;     /* set to IETF variant  */
			return new UUID(super.highBits(randomBytes), super.lowBits(randomBytes)).toString();
		} catch (NoSuchAlgorithmException e) {
			return Globals.DEFAULT_VALUE_STRING;
		}
	}
}
