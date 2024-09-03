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

import jakarta.xml.bind.annotation.*;

/**
 * <h2 class="en-US">Secure configure information define</h2>
 * <p class="en-US">Using for protect password in any configure files</p>
 * <h2 class="zh-CN">安全配置信息定义</h2>
 * <p class="zh-CN">用于在任何配置文件中保护密码</p>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 12, 2020 23:05:27 $
 */
@XmlRootElement(name = "secure_config", namespace = "https://nervousync.org/schemas/secure")
@XmlAccessorType(XmlAccessType.NONE)
public final class SecureConfig extends AbstractConfig {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = -4333190425770207630L;
	/**
	 * <span class="en-US">Secure config name</span>
	 * <span class="zh-CN">安全配置名称</span>
	 */
	@XmlElement(name = "secure_name")
	private String secureName;

	/**
	 * <h3 class="en-US">Constructor method for SecureConfig</h3>
	 * <h3 class="zh-CN">安全配置信息构造方法</h3>
	 */
	public SecureConfig() {
	}

	/**
	 * <h3 class="en-US">Getter method for secure config name</h3>
	 * <h3 class="zh-CN">安全配置名称的Getter方法</h3>
	 *
	 * @return <span class="en-US">Secure config name</span>
	 * <span class="zh-CN">安全配置名称</span>
	 */
	public String getSecureName() {
		return secureName;
	}

	/**
	 * <h3 class="en-US">Setter method for secure config name</h3>
	 * <h3 class="zh-CN">安全配置名称的Setter方法</h3>
	 *
	 * @param secureName <span class="en-US">Secure config name</span>
	 *                   <span class="zh-CN">安全配置名称</span>
	 */
	public void setSecureName(String secureName) {
		this.secureName = secureName;
	}
}
