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

import java.net.Proxy;

/**
 * <h2 class="en-US">Abstract proxy configure builder for Generics Type</h2>
 * <p class="en-US">
 * Current abstract class is using to integrate to another builder
 * which configure contains proxy configure information.
 * </p>
 * <h2 class="zh-CN">拥有父构造器的代理服务器配置信息抽象构造器</h2>
 * <p class="zh-CN">当前抽象构建器用于整合到包含代理服务器配置信息的其他配置构建器</p>
 *
 * @param <T> <span class="en-US">Generics Type Class</span>
 *            <span class="zh-CN">泛型类</span>
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 4, 2019 16:22:54 $
 */
public abstract class AbstractProxyConfigBuilder<T> extends AbstractBuilder<T> {
	/**
	 * <span class="en-US">Proxy configure information</span>
	 * <span class="zh-CN">代理服务器配置信息</span>
	 */
	protected final ProxyConfig proxyConfig;

	/**
	 * <h3 class="en-US">Protected constructor for AbstractProxyConfigBuilder</h3>
	 * <h3 class="zh-CN">AbstractProxyConfigBuilder的构造函数</h3>
	 *
	 * @param parentBuilder <span class="en-US">Generics Type instance</span>
	 *                      <span class="zh-CN">泛型类实例对象</span>
	 * @param proxyConfig   <span class="en-US">Proxy configure information</span>
	 *                      <span class="zh-CN">代理服务器配置信息</span>
	 */
	protected AbstractProxyConfigBuilder(final T parentBuilder, final ProxyConfig proxyConfig) {
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
	public final AbstractProxyConfigBuilder<T> proxyType(final Proxy.Type proxyType) {
		this.proxyConfig.setProxyType(proxyType);
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
	public final AbstractProxyConfigBuilder<T> serverConfig(final String serverAddress, final int serverPort) {
		if (!Proxy.Type.DIRECT.equals(this.proxyConfig.getProxyType())) {
			this.proxyConfig.setProxyAddress(serverAddress);
			this.proxyConfig.setProxyPort(serverPort);
		}
		return this;
	}

	/**
	 * <h3 class="en-US">Configure proxy server authenticate information</h3>
	 * <h3 class="zh-CN">配置代理服务器身份验证信息</h3>
	 *
	 * @param userName <span class="en-US">Authenticate username</span>
	 *                 <span class="zh-CN">身份认证用户名</span>
	 * @param passWord <span class="en-US">Authenticate password</span>
	 *                 <span class="zh-CN">身份认证密码</span>
	 * @return <span class="en-US">Current builder instance</span>
	 * <span class="zh-CN">当前构造器实例对象</span>
	 */
	public final AbstractProxyConfigBuilder<T> authenticator(final String userName, final String passWord) {
		if (!Proxy.Type.DIRECT.equals(this.proxyConfig.getProxyType())) {
			this.proxyConfig.setUserName(userName);
			this.proxyConfig.setPassword(passWord);
		}
		return this;
	}
}
