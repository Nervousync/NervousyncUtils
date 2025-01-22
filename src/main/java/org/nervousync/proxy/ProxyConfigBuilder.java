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
package org.nervousync.proxy;

import org.nervousync.builder.AbstractBuilder;
import org.nervousync.builder.ParentBuilder;
import org.nervousync.utils.DateTimeUtils;
import org.nervousync.utils.ObjectUtils;

import java.net.Proxy;

/**
 * <h2 class="en-US">Abstract proxy configure builder for Generics Type</h2>
 * <p class="en-US">
 * The current abstract class is using to integrate to another builder
 * which configure contains proxy configure information.
 * </p>
 * <h2 class="zh-CN">拥有父构造器的代理服务器配置信息抽象构造器</h2>
 * <p class="zh-CN">当前抽象构建器用于整合到包含代理服务器配置信息的其他配置构建器</p>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 4, 2019 16:22:54 $
 */
public final class ProxyConfigBuilder extends AbstractBuilder<ProxyConfig> {
	/**
	 * <span class="en-US">Proxy configure information</span>
	 * <span class="zh-CN">代理服务器配置信息</span>
	 */
	private final ProxyConfig proxyConfig;
	/**
	 * <h2 class="en-US">Configure information modified flag</h2>
	 * <h2 class="zh-CN">配置信息修改标记</h2>
	 */
	private boolean modified = Boolean.FALSE;

	/**
	 * <h3 class="en-US">Protected constructor for AbstractProxyConfigBuilder</h3>
	 * <h3 class="zh-CN">AbstractProxyConfigBuilder的构造函数</h3>
	 *
	 * @param proxyConfig <span class="en-US">Proxy configure information</span>
	 *                    <span class="zh-CN">代理服务器配置信息</span>
	 */
	public ProxyConfigBuilder(final ProxyConfig proxyConfig) {
		this(null, proxyConfig);
	}

	/**
	 * <h3 class="en-US">Protected constructor for AbstractProxyConfigBuilder</h3>
	 * <h3 class="zh-CN">AbstractProxyConfigBuilder的构造函数</h3>
	 *
	 * @param parentBuilder <span class="en-US">Generics Type instance</span>
	 *                      <span class="zh-CN">泛型类实例对象</span>
	 * @param proxyConfig   <span class="en-US">Proxy configure information</span>
	 *                      <span class="zh-CN">代理服务器配置信息</span>
	 */
	public ProxyConfigBuilder(final ParentBuilder parentBuilder, final ProxyConfig proxyConfig) {
		super(parentBuilder);
		this.proxyConfig = proxyConfig;
	}

	/**
	 * <h3 class="en-US">Configure proxy type</h3>
	 * <h3 class="zh-CN">配置代理服务器类型</h3>
	 *
	 * @param proxyType <span class="en-US">Enumeration value of proxy server</span>
	 *                  <span class="zh-CN">代理服务器类型枚举值</span>
	 * @return <span class="en-US">Current builder instance</span>
	 * <span class="zh-CN">当前构造器实例对象</span>
	 */
	public ProxyConfigBuilder proxyType(final Proxy.Type proxyType) {
		if (ObjectUtils.nullSafeEquals(this.proxyConfig.getProxyType(), proxyType)) {
			return this;
		}
		this.proxyConfig.setProxyType(proxyType);
		this.modified = Boolean.TRUE;
		return this;
	}

	/**
	 * <h3 class="en-US">Configure proxy server information</h3>
	 * <h3 class="zh-CN">配置代理服务器信息</h3>
	 *
	 * @param serverAddress <span class="en-US">Proxy server address</span>
	 *                      <span class="zh-CN">代理服务器地址</span>
	 * @param serverPort    <span class="en-US">Proxy server port</span>
	 *                      <span class="zh-CN">代理服务器端口号</span>
	 * @return <span class="en-US">Current builder instance</span>
	 * <span class="zh-CN">当前构造器实例对象</span>
	 */
	public ProxyConfigBuilder serverConfig(final String serverAddress, final int serverPort) {
		if (Proxy.Type.DIRECT.equals(this.proxyConfig.getProxyType())
				|| (ObjectUtils.nullSafeEquals(this.proxyConfig.getProxyAddress(), serverAddress)
						&& this.proxyConfig.getProxyPort() == serverPort)) {
			return this;
		}
		this.proxyConfig.setProxyAddress(serverAddress);
		this.proxyConfig.setProxyPort(serverPort);
		this.modified = Boolean.TRUE;
		return this;
	}

	/**
	 * <h3 class="en-US">Configure proxy servers authenticate information</h3>
	 * <h3 class="zh-CN">配置代理服务器身份验证信息</h3>
	 *
	 * @param userName <span class="en-US">Authenticate username</span>
	 *                 <span class="zh-CN">身份认证用户名</span>
	 * @param passWord <span class="en-US">Authenticate password</span>
	 *                 <span class="zh-CN">身份认证密码</span>
	 * @return <span class="en-US">Current builder instance</span>
	 * <span class="zh-CN">当前构造器实例对象</span>
	 */
	public ProxyConfigBuilder authenticator(final String userName, final String passWord) {
		if (Proxy.Type.DIRECT.equals(this.proxyConfig.getProxyType())
				|| (ObjectUtils.nullSafeEquals(this.proxyConfig.getUserName(), userName)
						&& ObjectUtils.nullSafeEquals(this.proxyConfig.getPassword(), passWord))) {
			return this;
		}
		this.proxyConfig.setUserName(userName);
		this.proxyConfig.setPassword(passWord);
		this.modified = Boolean.TRUE;
		return this;
	}

	@Override
	public ProxyConfig confirm() {
		if (this.modified) {
			this.proxyConfig.setLastModified(DateTimeUtils.currentUTCTimeMillis());
		}
		return this.proxyConfig;
	}
}
