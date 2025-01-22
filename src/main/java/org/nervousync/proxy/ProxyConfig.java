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

import java.net.Proxy.Type;

import jakarta.xml.bind.annotation.*;
import org.nervousync.annotations.configs.Password;
import org.nervousync.beans.core.BeanObject;
import org.nervousync.commons.Globals;

/**
 * <h2 class="en-US">Proxy server configure</h2>
 * <h2 class="zh-CN">代理服务器配置信息</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 4, 2018 16:05:54 $
 */
@XmlType(name = "proxy_config", namespace = "https://nervousync.org/schemas/proxy")
@XmlRootElement(name = "proxy_config", namespace = "https://nervousync.org/schemas/proxy")
@XmlAccessorType(XmlAccessType.NONE)
public final class ProxyConfig extends BeanObject {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = -5386443812775715018L;
	/**
	 * <span class="en-US">Enumeration value of proxy type</span>
	 * <span class="zh-CN">代理服务器类型枚举值</span>
	 */
	@XmlElement(name = "type")
	private Type proxyType = Type.DIRECT;
	/**
	 * <span class="en-US">Proxy server address</span>
	 * <span class="zh-CN">代理服务器地址</span>
	 */
	@XmlElement(name = "address")
	private String proxyAddress = Globals.DEFAULT_VALUE_STRING;
	/**
	 * <span class="en-US">Proxy server port</span>
	 * <span class="zh-CN">代理服务器端口号</span>
	 */
	@XmlElement(name = "port")
	private int proxyPort = Globals.DEFAULT_VALUE_INT;
	/**
	 * <span class="en-US">Authenticate username</span>
	 * <span class="zh-CN">身份认证用户名</span>
	 */
	@XmlElement(name = "username")
	private String userName = Globals.DEFAULT_VALUE_STRING;
	/**
	 * <span class="en-US">Authenticate password</span>
	 * <span class="zh-CN">身份认证密码</span>
	 */
	@Password
	@XmlElement(name = "password")
	private String password = Globals.DEFAULT_VALUE_STRING;
	/**
	 * <span class="en-US">Last modified timestamp</span>
	 * <span class="zh-CN">最后修改时间戳</span>
	 */
	@XmlElement(name = "last_modified")
	private long lastModified = Globals.DEFAULT_VALUE_LONG;

	/**
	 * <h3 class="en-US">Constructor method for ProxyConfig</h3>
	 * <h3 class="zh-CN">ProxyConfig构造方法</h3>
	 */
	public ProxyConfig() {
	}

	/**
	 * <h3 class="en-US">Static method for create redirect ProxyConfig instance</h3>
	 * <h3 class="zh-CN">静态方法用于创建无代理的代理服务器配置信息实例对象</h3>
	 *
	 * @return <span class="en-US">Generated ProxyConfig instance</span>
	 * <span class="zh-CN">生成的代理服务器配置信息实例对象</span>
	 */
	public static ProxyConfig redirect() {
		return new ProxyConfig();
	}

	/**
	 * <h3 class="en-US">Getter method for proxy type</h3>
	 * <h3 class="zh-CN">代理服务器类型的Getter方法</h3>
	 *
	 * @return <span class="en-US">Enumeration value of proxy type</span>
	 * <span class="zh-CN">代理服务器类型枚举值</span>
	 */
	public Type getProxyType() {
		return proxyType;
	}

	/**
	 * <h3 class="en-US">Setter method for proxy type</h3>
	 * <h3 class="zh-CN">代理服务器类型的Setter方法</h3>
	 *
	 * @param proxyType <span class="en-US">Enumeration value of proxy type</span>
	 *                  <span class="zh-CN">代理服务器类型枚举值</span>
	 */
	public void setProxyType(Type proxyType) {
		this.proxyType = proxyType;
	}

	/**
	 * <h3 class="en-US">Getter method for proxy type</h3>
	 * <h3 class="zh-CN">代理服务器类型的Getter方法</h3>
	 *
	 * @return <span class="en-US">Proxy server address</span>
	 * <span class="zh-CN">代理服务器地址</span>
	 */
	public String getProxyAddress() {
		return proxyAddress;
	}

	/**
	 * <h3 class="en-US">Setter method for proxy type</h3>
	 * <h3 class="zh-CN">代理服务器类型的Setter方法</h3>
	 *
	 * @param proxyAddress <span class="en-US">Proxy server address</span>
	 *                     <span class="zh-CN">代理服务器地址</span>
	 */
	public void setProxyAddress(String proxyAddress) {
		this.proxyAddress = proxyAddress;
	}

	/**
	 * <h3 class="en-US">Getter method for proxy type</h3>
	 * <h3 class="zh-CN">代理服务器类型的Getter方法</h3>
	 *
	 * @return <span class="en-US">Proxy server port</span>
	 * <span class="zh-CN">代理服务器端口号</span>
	 */
	public int getProxyPort() {
		return proxyPort;
	}

	/**
	 * <h3 class="en-US">Setter method for proxy type</h3>
	 * <h3 class="zh-CN">代理服务器类型的Setter方法</h3>
	 *
	 * @param proxyPort <span class="en-US">Proxy server port</span>
	 *                  <span class="zh-CN">代理服务器端口号</span>
	 */
	public void setProxyPort(int proxyPort) {
		this.proxyPort = proxyPort;
	}

	/**
	 * <h3 class="en-US">Getter method for proxy type</h3>
	 * <h3 class="zh-CN">代理服务器类型的Getter方法</h3>
	 *
	 * @return <span class="en-US">Authenticate username</span>
	 * <span class="zh-CN">身份认证用户名</span>
	 */
	public String getUserName() {
		return userName;
	}

	/**
	 * <h3 class="en-US">Setter method for proxy type</h3>
	 * <h3 class="zh-CN">代理服务器类型的Setter方法</h3>
	 *
	 * @param userName <span class="en-US">Authenticate username</span>
	 *                 <span class="zh-CN">身份认证用户名</span>
	 */
	public void setUserName(String userName) {
		this.userName = userName;
	}

	/**
	 * <h3 class="en-US">Getter method for proxy type</h3>
	 * <h3 class="zh-CN">代理服务器类型的Getter方法</h3>
	 *
	 * @return <span class="en-US">Authenticate password</span>
	 * <span class="zh-CN">身份认证密码</span>
	 */
	public String getPassword() {
		return password;
	}

	/**
	 * <h3 class="en-US">Setter method for proxy type</h3>
	 * <h3 class="zh-CN">代理服务器类型的Setter方法</h3>
	 *
	 * @param password <span class="en-US">Authenticate password</span>
	 *                 <span class="zh-CN">身份认证密码</span>
	 */
	public void setPassword(String password) {
		this.password = password;
	}

	/**
	 * <h3 class="en-US">Getter method for the last modified timestamp</h3>
	 * <h3 class="zh-CN">最后修改时间戳的Getter方法</h3>
	 *
	 * @return <span class="en-US">Last modified timestamp</span>
	 * <span class="zh-CN">最后修改时间戳</span>
	 */
	public long getLastModified() {
		return this.lastModified;
	}

	/**
	 * <h3 class="en-US">Setter method for the last modified timestamp</h3>
	 * <h3 class="zh-CN">最后修改时间戳的Setter方法</h3>
	 *
	 * @param lastModified <span class="en-US">Last modified timestamp</span>
	 *                     <span class="zh-CN">最后修改时间戳</span>
	 */
	public void setLastModified(final long lastModified) {
		this.lastModified = lastModified;
	}
}
