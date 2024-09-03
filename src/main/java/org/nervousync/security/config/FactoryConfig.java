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

package org.nervousync.security.config;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * <h2 class="en-US">Secure factory configure information define</h2>
 * <p class="en-US">Using for protect custom secure configure information</p>
 * <h2 class="zh-CN">安全工厂配置信息定义</h2>
 * <p class="zh-CN">用于保护安全配置信息</p>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 12, 2020 23:13:21 $
 */
@XmlRootElement(name = "secure_factory", namespace = "https://nervousync.org/schemas/secure")
@XmlAccessorType(XmlAccessType.NONE)
public final class FactoryConfig extends AbstractConfig {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 5989686893171586402L;

	public FactoryConfig() {
	}
}
