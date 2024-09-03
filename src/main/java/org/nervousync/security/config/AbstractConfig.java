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
import jakarta.xml.bind.annotation.XmlElement;
import org.nervousync.beans.core.BeanObject;
import org.nervousync.security.factory.SecureFactory;

/**
 * <h2 class="en-US">Abstract class of security configuration information</h2>
 * <h2 class="zh-CN">安全配置信息抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 12, 2020 22:10:21 $
 */
@XmlAccessorType(XmlAccessType.NONE)
public abstract class AbstractConfig extends BeanObject {

	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 2626987266160131570L;
	/**
	 * <span class="en-US">Secure algorithm</span>
	 * <span class="zh-CN">安全算法</span>
	 */
	@XmlElement(name = "secure_algorithm")
	private SecureFactory.SecureAlgorithm secureAlgorithm = null;
	/**
	 * <span class="en-US">Secure key</span>
	 * <span class="zh-CN">安全密钥</span>
	 */
	@XmlElement(name = "secure_key")
	private String secureKey = null;

	/**
	 * <h3 class="en-US">Getter method for secure algorithm</h3>
	 * <h3 class="zh-CN">安全算法的Getter方法</h3>
	 *
	 * @return <span class="en-US">Secure algorithm</span>
	 * <span class="zh-CN">安全算法</span>
	 */
	public SecureFactory.SecureAlgorithm getSecureAlgorithm() {
		return secureAlgorithm;
	}

	/**
	 * <h3 class="en-US">Setter method for secure algorithm</h3>
	 * <h3 class="zh-CN">安全算法的Setter方法</h3>
	 *
	 * @param secureAlgorithm <span class="en-US">Secure algorithm</span>
	 *                        <span class="zh-CN">安全算法</span>
	 */
	public void setSecureAlgorithm(SecureFactory.SecureAlgorithm secureAlgorithm) {
		this.secureAlgorithm = secureAlgorithm;
	}

	/**
	 * <h3 class="en-US">Getter method for secure key</h3>
	 * <h3 class="zh-CN">安全密钥的Getter方法</h3>
	 *
	 * @return <span class="en-US">Secure key</span>
	 * <span class="zh-CN">安全密钥</span>
	 */
	public String getSecureKey() {
		return secureKey;
	}

	/**
	 * <h3 class="en-US">Setter method for secure key</h3>
	 * <h3 class="zh-CN">安全密钥的Setter方法</h3>
	 *
	 * @param secureKey <span class="en-US">Secure key</span>
	 *                  <span class="zh-CN">安全密钥</span>
	 */
	public void setSecureKey(String secureKey) {
		this.secureKey = secureKey;
	}
}
