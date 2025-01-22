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
import org.nervousync.beans.core.BeanObject;

import java.util.ArrayList;
import java.util.List;

/**
 * <h2 class="en-US">Defined security configuration information</h2>
 * <h2 class="zh-CN">定义的安全配置信息</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 12, 2020 23:15:46 $
 */
@XmlRootElement(name = "secure_settings", namespace = "https://nervousync.org/schemas/secure")
@XmlAccessorType(XmlAccessType.NONE)
public final class SecureSettings extends BeanObject {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = -5036977038474319966L;

	/**
	 * <span class="en-US">System default security configuration information</span>
	 * <span class="zh-CN">系统默认安全配置信息</span>
	 */
	@XmlElement(name = "system_secure")
	private SecureConfig systemSecure;
	/**
	 * <span class="en-US">Customized security configuration information list</span>
	 * <span class="zh-CN">自定义安全配置信息列表</span>
	 */
	@XmlElement(name = "secure_config")
	@XmlElementWrapper(name = "secure_list")
	private List<SecureConfig> customSecures = new ArrayList<>();

	/**
	 * <h3 class="en-US">Getter method for system default security configuration information</h3>
	 * <h3 class="zh-CN">系统默认安全配置信息的Getter方法</h3>
	 *
	 * @return <span class="en-US">System default security configuration information</span>
	 * <span class="zh-CN">系统默认安全配置信息</span>
	 */
	public SecureConfig getSystemSecure() {
		return systemSecure;
	}

	/**
	 * <h3 class="en-US">Setter method for system default security configuration information</h3>
	 * <h3 class="zh-CN">系统默认安全配置信息的Setter方法</h3>
	 *
	 * @param systemSecure <span class="en-US">System default security configuration information</span>
	 *                     <span class="zh-CN">系统默认安全配置信息</span>
	 */
	public void setSystemSecure(SecureConfig systemSecure) {
		this.systemSecure = systemSecure;
	}

	/**
	 * <h3 class="en-US">Getter method for customized security configuration information list</h3>
	 * <h3 class="zh-CN">自定义安全配置信息列表的Getter方法</h3>
	 *
	 * @return <span class="en-US">Customized security configuration information list</span>
	 * <span class="zh-CN">自定义安全配置信息列表</span>
	 */
	public List<SecureConfig> getCustomSecures() {
		return customSecures;
	}

	/**
	 * <h3 class="en-US">Setter method for customized security configuration information list</h3>
	 * <h3 class="zh-CN">自定义安全配置信息列表的Setter方法</h3>
	 *
	 * @param customSecures <span class="en-US">Customized security configuration information list</span>
	 *                      <span class="zh-CN">自定义安全配置信息列表</span>
	 */
	public void setCustomSecures(List<SecureConfig> customSecures) {
		this.customSecures = customSecures;
	}
}
