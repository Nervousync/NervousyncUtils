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
package org.nervousync.mail.config;

import jakarta.xml.bind.annotation.*;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.nervousync.annotations.configs.Password;
import org.nervousync.beans.core.BeanObject;
import org.nervousync.beans.transfer.enumerations.MailProtocolAdapter;
import org.nervousync.commons.Globals;
import org.nervousync.enumerations.mail.MailProtocol;
import org.nervousync.proxy.ProxyConfig;

/**
 * <h2 class="en-US">Mail configure information define</h2>
 * <h2 class="zh-CN">邮件配置信息定义</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 31, 2021 19:06:18 $
 */
@XmlRootElement(name = "mail_config", namespace = "https://nervousync.org/schemas/mail")
@XmlAccessorType(XmlAccessType.NONE)
public final class MailConfig extends BeanObject {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = -506685998495058905L;
	/**
	 * <span class="en-US">Mail account username</span>
	 * <span class="zh-CN">邮件账户用户名</span>
	 */
	@XmlElement(name = "username")
	private String userName;
	/**
	 * <span class="en-US">Mail account password</span>
	 * <span class="zh-CN">邮件账户密码</span>
	 */
	@Password
	@XmlElement(name = "password")
	private String password;
	/**
	 * <span class="en-US">Proxy configure information</span>
	 * <span class="zh-CN">代理服务器配置信息</span>
	 */
	@XmlElement(name = "proxy_config", namespace = "https://nervousync.org/schemas/proxy")
	private ProxyConfig proxyConfig = ProxyConfig.redirect();
	/**
	 * <span class="en-US">Mail send server config</span>
	 * <span class="zh-CN">邮件发送服务器配置信息</span>
	 */
	@XmlElement(name = "send_config")
	private ServerConfig sendConfig;
	/**
	 * <span class="en-US">Mail receive server config</span>
	 * <span class="zh-CN">邮件接收服务器配置信息</span>
	 */
	@XmlElement(name = "receive_config")
	private ServerConfig receiveConfig;
	/**
	 * <span class="en-US">Attaches the file storage path</span>
	 * <span class="zh-CN">附件文件的保存地址</span>
	 */
	@XmlElement(name = "storage_path")
	private String storagePath;
	/**
	 * <span class="en-US">Base64 encoded binary data bytes of x509 certificate</span>
	 * <p class="en-US">Using for email signature verify</p>
	 * <span class="zh-CN">Base64编码的x509证书二进制数组</span>
	 * <p class="zh-CN">用于电子邮件签名验证</p>
	 */
	@XmlElement
	private String certificate;
	/**
	 * <span class="en-US">Base64 encoded binary data bytes of private key</span>
	 * <p class="en-US">Using for email signature</p>
	 * <span class="zh-CN">Base64编码的私有密钥二进制数组</span>
	 * <p class="zh-CN">用于电子邮件签名</p>
	 */
	@XmlElement(name = "private_key")
	private String privateKey;
	/**
	 * <span class="en-US">Last modified timestamp</span>
	 * <span class="zh-CN">最后修改时间戳</span>
	 */
	@XmlElement(name = "last_modified")
	private long lastModified = Globals.DEFAULT_VALUE_LONG;

	/**
	 * <h3 class="en-US">Constructor method for MailConfig</h3>
	 * <h3 class="zh-CN">MailConfig构造方法</h3>
	 */
	public MailConfig() {
		this.certificate = Globals.DEFAULT_VALUE_STRING;
		this.privateKey = Globals.DEFAULT_VALUE_STRING;
	}

	/**
	 * <h3 class="en-US">Getter method for mail account username</h3>
	 * <h3 class="zh-CN">邮件账户用户名的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail account username</span>
	 * <span class="zh-CN">邮件账户用户名</span>
	 */
	public String getUserName() {
		return userName;
	}

	/**
	 * <h3 class="en-US">Setter method for mail account username</h3>
	 * <h3 class="zh-CN">邮件账户用户名的Setter方法</h3>
	 *
	 * @param userName <span class="en-US">Mail account username</span>
	 *                 <span class="zh-CN">邮件账户用户名</span>
	 */
	public void setUserName(String userName) {
		this.userName = userName;
	}

	/**
	 * <h3 class="en-US">Getter method for mail account password</h3>
	 * <h3 class="zh-CN">邮件账户密码的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail account password</span>
	 * <span class="zh-CN">邮件账户密码</span>
	 */
	public String getPassword() {
		return password;
	}

	/**
	 * <h3 class="en-US">Setter method for mail account password</h3>
	 * <h3 class="zh-CN">邮件账户密码的Setter方法</h3>
	 *
	 * @param password <span class="en-US">Mail account password</span>
	 *                 <span class="zh-CN">邮件账户密码</span>
	 */
	public void setPassword(String password) {
		this.password = password;
	}

	/**
	 * <h3 class="en-US">Getter method for proxy configure information</h3>
	 * <h3 class="zh-CN">代理服务器配置信息的Getter方法</h3>
	 *
	 * @return <span class="en-US">Proxy configure information</span>
	 * <span class="zh-CN">代理服务器配置信息</span>
	 */
	public ProxyConfig getProxyConfig() {
		return proxyConfig;
	}

	/**
	 * <h3 class="en-US">Setter method for proxy configure information</h3>
	 * <h3 class="zh-CN">代理服务器配置信息的Setter方法</h3>
	 *
	 * @param proxyConfig <span class="en-US">Proxy configure information</span>
	 *                    <span class="zh-CN">代理服务器配置信息</span>
	 */
	public void setProxyConfig(ProxyConfig proxyConfig) {
		this.proxyConfig = proxyConfig;
	}

	/**
	 * <h3 class="en-US">Getter method for mail sends server config</h3>
	 * <h3 class="zh-CN">邮件发送服务器配置信息的Getter方法</h3>
	 *
	 * <span class="en-US">Mail send server config</span>
	 * <span class="zh-CN">邮件发送服务器配置信息</span>
	 */
	public ServerConfig getSendConfig() {
		return sendConfig;
	}

	/**
	 * <h3 class="en-US">Setter method for mail send server config</h3>
	 * <h3 class="zh-CN">邮件发送服务器配置信息的Setter方法</h3>
	 *
	 * @param sendConfig <span class="en-US">Mail send server config</span>
	 *                   <span class="zh-CN">邮件发送服务器配置信息</span>
	 */
	public void setSendConfig(ServerConfig sendConfig) {
		this.sendConfig = sendConfig;
	}

	/**
	 * <h3 class="en-US">Getter method for mail receives server config</h3>
	 * <h3 class="zh-CN">邮件接收服务器配置信息的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail receive server config</span>
	 * <span class="zh-CN">邮件接收服务器配置信息</span>
	 */
	public ServerConfig getReceiveConfig() {
		return receiveConfig;
	}

	/**
	 * <h3 class="en-US">Setter method for mail receives server config</h3>
	 * <h3 class="zh-CN">邮件接收服务器配置信息的Setter方法</h3>
	 *
	 * @param receiveConfig <span class="en-US">Mail receive server config</span>
	 *                      <span class="zh-CN">邮件接收服务器配置信息</span>
	 */
	public void setReceiveConfig(ServerConfig receiveConfig) {
		this.receiveConfig = receiveConfig;
	}

	/**
	 * <h3 class="en-US">Getter method for attaches the file storage path</h3>
	 * <h3 class="zh-CN">附件文件的保存地址的Getter方法</h3>
	 *
	 * @return <span class="en-US">Attaches the file storage path</span>
	 * <span class="zh-CN">附件文件的保存地址</span>
	 */
	public String getStoragePath() {
		return storagePath;
	}

	/**
	 * <h3 class="en-US">Setter method for attaches the file storage path</h3>
	 * <h3 class="zh-CN">附件文件的保存地址的Setter方法</h3>
	 *
	 * @param storagePath <span class="en-US">Attaches the file storage path</span>
	 *                    <span class="zh-CN">附件文件的保存地址</span>
	 */
	public void setStoragePath(String storagePath) {
		this.storagePath = storagePath;
	}

	/**
	 * <h3 class="en-US">Getter method for base64 encoded binary data bytes of x509 certificate</h3>
	 * <h3 class="zh-CN">Base64编码的x509证书二进制数组的Getter方法</h3>
	 *
	 * @return <span class="en-US">Base64 encoded binary data bytes of x509 certificate</span>
	 * <span class="zh-CN">Base64编码的x509证书二进制数组</span>
	 */
	public String getCertificate() {
		return certificate;
	}

	/**
	 * <h3 class="en-US">Setter method for base64 encoded binary data bytes of x509 certificate</h3>
	 * <h3 class="zh-CN">Base64编码的x509证书二进制数组的Setter方法</h3>
	 *
	 * @param certificate <span class="en-US">Base64 encoded binary data bytes of x509 certificate</span>
	 *                    <span class="zh-CN">Base64编码的x509证书二进制数组</span>
	 */
	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}

	/**
	 * <h3 class="en-US">Getter method for base64 encoded binary data bytes of the private key</h3>
	 * <h3 class="zh-CN">Base64编码的私有密钥二进制数组的Getter方法</h3>
	 *
	 * @return <span class="en-US">Base64 encoded binary data bytes of private key</span>
	 * <span class="zh-CN">Base64编码的私有密钥二进制数组</span>
	 */
	public String getPrivateKey() {
		return privateKey;
	}

	/**
	 * <h3 class="en-US">Setter method for base64 encoded binary data bytes of the private key</h3>
	 * <h3 class="zh-CN">Base64编码的私有密钥二进制数组的Setter方法</h3>
	 *
	 * @param privateKey <span class="en-US">Base64 encoded binary data bytes of private key</span>
	 *                   <span class="zh-CN">Base64编码的私有密钥二进制数组</span>
	 */
	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
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

	/**
	 * <h2 class="en-US">Mail server configure information define</h2>
	 * <h2 class="zh-CN">邮件服务器配置信息定义</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0.0 $ $Date: Jul 31, 2021 19:09:18 $
	 */
	@XmlType(name = "server_config", namespace = "https://nervousync.org/schemas/mail")
	@XmlAccessorType(XmlAccessType.NONE)
	public static final class ServerConfig extends BeanObject {
		/**
		 * <span class="en-US">Serial version UID</span>
		 * <span class="zh-CN">序列化UID</span>
		 */
		private static final long serialVersionUID = -1768113760096890529L;
		/**
		 * <span class="en-US">Is send server configure</span>
		 * <span class="zh-CN">是发送服务器配置信息</span>
		 */
		private final boolean sendConfig;
		/**
		 * <span class="en-US">Mail server domain name</span>
		 * <span class="zh-CN">邮件服务器域名</span>
		 */
		@XmlElement(name = "host_name")
		private String hostName;
		/**
		 * <span class="en-US">Mail server port</span>
		 * <span class="zh-CN">邮件服务器端口号</span>
		 */
		@XmlElement(name = "host_port")
		private int hostPort;
		/**
		 * <span class="en-US">Using secure connection to host server</span>
		 * <span class="zh-CN">使用安全连接到邮件服务器</span>
		 */
		@XmlElement(name = "ssl")
		private boolean ssl;
		/**
		 * <span class="en-US">Host server authenticates login</span>
		 * <span class="zh-CN">邮件服务器需要身份验证</span>
		 */
		@XmlElement(name = "auth_login")
		private boolean authLogin;
		/**
		 * <span class="en-US">Mail server protocol</span>
		 * <span class="zh-CN">邮件服务器协议</span>
		 */
		@XmlJavaTypeAdapter(MailProtocolAdapter.class)
		@XmlElement(name = "protocol")
		private MailProtocol protocolOption;
		/**
		 * <span class="en-US">Connection timeout(Unit: seconds)</span>
		 * <span class="zh-CN">连接超时时间（单位：秒）</span>
		 */
		@XmlElement(name = "connection_timeout")
		private int connectionTimeout = 5;
		/**
		 * <span class="en-US">Process timeout(Unit: seconds)</span>
		 * <span class="zh-CN">操作超时时间（单位：秒）</span>
		 */
		@XmlElement(name = "process_timeout")
		private int processTimeout = 5;
		/**
		 * <span class="en-US">Last modified timestamp</span>
		 * <span class="zh-CN">最后修改时间戳</span>
		 */
		@XmlElement(name = "last_modified")
		private long lastModified = Globals.DEFAULT_VALUE_LONG;

		/**
		 * <h3 class="en-US">Constructor method for ServerConfig</h3>
		 * <h3 class="zh-CN">ServerConfig构造方法</h3>
		 */
		public ServerConfig() {
			this.hostName = Globals.DEFAULT_VALUE_STRING;
			this.sendConfig = Boolean.FALSE;
		}

		/**
		 * <h3 class="en-US">Constructor method for ServerConfig</h3>
		 * <h3 class="zh-CN">ServerConfig构造方法</h3>
		 *
		 * @param sendConfig <span class="en-US">Is send server configure</span>
		 *                   <span class="zh-CN">是发送服务器配置信息</span>
		 */
		public ServerConfig(final boolean sendConfig) {
			this.hostName = Globals.DEFAULT_VALUE_STRING;
			this.sendConfig = sendConfig;
		}

		/**
		 * <h3 class="en-US">Getter method for is send server configure</h3>
		 * <h3 class="zh-CN">是发送服务器配置信息的Getter方法</h3>
		 *
		 * @return <span class="en-US">Is send server configure</span>
		 * <span class="zh-CN">是发送服务器配置信息</span>
		 */
		public boolean isSendConfig() {
			return this.sendConfig;
		}

		/**
		 * <h3 class="en-US">Getter method for mail server domain name</h3>
		 * <h3 class="zh-CN">邮件服务器域名的Getter方法</h3>
		 *
		 * @return <span class="en-US">Mail server domain name</span>
		 * <span class="zh-CN">邮件服务器域名</span>
		 */
		public String getHostName() {
			return hostName;
		}

		/**
		 * <h3 class="en-US">Setter method for mail server domain name</h3>
		 * <h3 class="zh-CN">邮件服务器域名的Setter方法</h3>
		 *
		 * @param hostName <span class="en-US">Mail server domain name</span>
		 *                 <span class="zh-CN">邮件服务器域名</span>
		 */
		public void setHostName(String hostName) {
			this.hostName = hostName;
		}

		/**
		 * <h3 class="en-US">Getter method for mail server port</h3>
		 * <h3 class="zh-CN">邮件服务器端口号的Getter方法</h3>
		 *
		 * @return <span class="en-US">Mail server port</span>
		 * <span class="zh-CN">邮件服务器端口号</span>
		 */
		public int getHostPort() {
			return hostPort;
		}

		/**
		 * <h3 class="en-US">Setter method for mail server port</h3>
		 * <h3 class="zh-CN">邮件服务器端口号的Setter方法</h3>
		 *
		 * @param hostPort <span class="en-US">Mail server port</span>
		 *                 <span class="zh-CN">邮件服务器端口号</span>
		 */
		public void setHostPort(int hostPort) {
			this.hostPort = hostPort;
		}

		/**
		 * <h3 class="en-US">Getter method for using secure connection to host server</h3>
		 * <h3 class="zh-CN">使用安全连接到邮件服务器的Getter方法</h3>
		 *
		 * @return <span class="en-US">Using secure connection to host server</span>
		 * <span class="zh-CN">使用安全连接到邮件服务器</span>
		 */
		public boolean isSsl() {
			return ssl;
		}

		/**
		 * <h3 class="en-US">Setter method for using secure connection to host server</h3>
		 * <h3 class="zh-CN">使用安全连接到邮件服务器的Setter方法</h3>
		 *
		 * @param ssl <span class="en-US">Using secure connection to host server</span>
		 *            <span class="zh-CN">使用安全连接到邮件服务器</span>
		 */
		public void setSsl(boolean ssl) {
			this.ssl = ssl;
		}

		/**
		 * <h3 class="en-US">Getter method for host server authenticate login</h3>
		 * <h3 class="zh-CN">邮件服务器需要身份验证的Getter方法</h3>
		 *
		 * @return <span class="en-US">Host server authenticates login</span>
		 * <span class="zh-CN">邮件服务器需要身份验证</span>
		 */
		public boolean isAuthLogin() {
			return authLogin;
		}

		/**
		 * <h3 class="en-US">Setter method for host server authenticate login</h3>
		 * <h3 class="zh-CN">邮件服务器需要身份验证的Setter方法</h3>
		 *
		 * @param authLogin <span class="en-US">Host server authenticates login</span>
		 *                  <span class="zh-CN">邮件服务器需要身份验证</span>
		 */
		public void setAuthLogin(boolean authLogin) {
			this.authLogin = authLogin;
		}

		/**
		 * <h3 class="en-US">Getter method for mail server protocol</h3>
		 * <h3 class="zh-CN">邮件服务器协议的Getter方法</h3>
		 *
		 * @return <span class="en-US">Mail server protocol</span>
		 * <span class="zh-CN">邮件服务器协议</span>
		 */
		public MailProtocol getProtocolOption() {
			return protocolOption;
		}

		/**
		 * <h3 class="en-US">Setter method for mail server protocol</h3>
		 * <h3 class="zh-CN">邮件服务器协议的Setter方法</h3>
		 *
		 * @param protocolOption <span class="en-US">Mail server protocol</span>
		 *                       <span class="zh-CN">邮件服务器协议</span>
		 */
		public void setProtocolOption(MailProtocol protocolOption) {
			this.protocolOption = protocolOption;
		}

		/**
		 * <h3 class="en-US">Getter method for connection timeout</h3>
		 * <h3 class="zh-CN">连接超时时间的Getter方法</h3>
		 *
		 * @return <span class="en-US">Connection timeout(Unit: seconds)</span>
		 * <span class="zh-CN">连接超时时间（单位：秒）</span>
		 */
		public int getConnectionTimeout() {
			return connectionTimeout;
		}

		/**
		 * <h3 class="en-US">Setter method for connection timeout</h3>
		 * <h3 class="zh-CN">连接超时时间的Setter方法</h3>
		 *
		 * @param connectionTimeout <span class="en-US">Connection timeout(Unit: seconds)</span>
		 *                          <span class="zh-CN">连接超时时间（单位：秒）</span>
		 */
		public void setConnectionTimeout(int connectionTimeout) {
			this.connectionTimeout = connectionTimeout;
		}

		/**
		 * <h3 class="en-US">Getter method for process timeout</h3>
		 * <h3 class="zh-CN">操作超时时间的Getter方法</h3>
		 *
		 * @return <span class="en-US">Process timeout(Unit: seconds)</span>
		 * <span class="zh-CN">操作超时时间（单位：秒）</span>
		 */
		public int getProcessTimeout() {
			return processTimeout;
		}

		/**
		 * <h3 class="en-US">Setter method for process timeout</h3>
		 * <h3 class="zh-CN">操作超时时间的Setter方法</h3>
		 *
		 * @param processTimeout <span class="en-US">Process timeout(Unit: seconds)</span>
		 *                       <span class="zh-CN">操作超时时间（单位：秒）</span>
		 */
		public void setProcessTimeout(int processTimeout) {
			this.processTimeout = processTimeout;
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
}
