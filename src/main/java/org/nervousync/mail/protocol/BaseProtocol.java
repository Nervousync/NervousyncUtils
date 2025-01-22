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
package org.nervousync.mail.protocol;

import java.io.Serializable;
import java.security.Security;
import java.util.*;

import org.nervousync.commons.Globals;
import org.nervousync.proxy.ProxyConfig;
import org.nervousync.enumerations.mail.MailProtocol;
import org.nervousync.mail.config.MailConfig;
import org.nervousync.utils.StringUtils;

/**
 * <h2 class="en-US">Abstract class of JavaMail protocol</h2>
 * <h2 class="zh-CN">JavaMail的协议抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 31, 2012 19:07:08 $
 */
public abstract class BaseProtocol implements Serializable {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 6441571927997267674L;
	/**
	 * <span class="en-US">Default SSL socket factory class, using for connecting to ssl mail server</span>
	 * <span class="zh-CN">默认的安全套接字工厂类，用于连接到电子邮件服务器时使用安全连接</span>
	 */
	private static final String SSL_FACTORY_CLASS = "javax.net.ssl.SSLSocketFactory";
	/**
	 * <span class="en-US">Protocol key name of connecting to mail server store</span>
	 * <span class="zh-CN">连接到电子邮件服务器的通讯协议类型键值名</span>
	 */
	private static final String MAIL_STORE_PROTOCOL = "mail.store.protocol";
	/**
	 * <span class="en-US">Protocol key name of connecting to mail server transport</span>
	 * <span class="zh-CN">连接到电子邮件服务器的传输协议类型键值名</span>
	 */
	private static final String MAIL_TRANSPORT_PROTOCOL = "mail.transport.protocol";
	/**
	 * <span class="en-US">Connect timeout value</span>
	 * <span class="zh-CN">连接超时时间</span>
	 */
	protected String connectionTimeoutParam;
	/**
	 * <span class="en-US">Mail server domain name</span>
	 * <span class="zh-CN">邮件服务器域名</span>
	 */
	protected String hostParam;
	/**
	 * <span class="en-US">Mail server port</span>
	 * <span class="zh-CN">邮件服务器端口号</span>
	 */
	protected String portParam;
	/**
	 * <span class="en-US">Process timeout value</span>
	 * <span class="zh-CN">操作超时时间</span>
	 */
	protected String timeoutParam;
	/**
	 * <span class="en-US">Proxy configure information</span>
	 * <span class="zh-CN">代理服务器配置信息</span>
	 */
	private final ProxyConfig proxyConfig;

	/**
	 * <h3 class="en-US">Constructor method for BaseProtocol</h3>
	 * <h3 class="zh-CN">BaseProtocol构造方法</h3>
	 *
	 * @param proxyConfig <span class="en-US">Proxy configure information</span>
	 *                    <span class="zh-CN">代理服务器配置信息</span>
	 */
	protected BaseProtocol(final ProxyConfig proxyConfig) {
		this.proxyConfig = proxyConfig;
	}

	/**
	 * <h3 class="en-US">Convert given e-mail server configure instance to Properties instance</h3>
	 * <p class="en-US">Generated Properties instance is using for connecting to E-mail server </p>
	 * <h3 class="zh-CN">转换给定的电子邮件配置实例对象为Properties实例对象</h3>
	 * <p class="zh-CN">生成的Properties实例对象用于连接到电子邮件服务器</p>
	 *
	 * @param serverConfig <span class="en-US">Server configure information</span>
	 *                     <span class="zh-CN">服务器配置</span>
	 * @return <span class="en-US">Generated Properties instance</span>
	 * <span class="zh-CN">生成的Properties实例对象</span>
	 */
	public final Properties readConfig(final MailConfig.ServerConfig serverConfig) {
		Properties properties = new Properties();

		properties.setProperty(this.hostParam, serverConfig.getHostName());
		int port = serverConfig.getHostPort();
		if (port != Globals.DEFAULT_VALUE_INT) {
			properties.setProperty(portParam, Integer.toString(port));
		}

		if (serverConfig.getConnectionTimeout() > 0) {
			properties.setProperty(connectionTimeoutParam,
					Integer.toString(serverConfig.getConnectionTimeout() * 1000));
		}
		if (serverConfig.getProcessTimeout() > 0) {
			properties.setProperty(timeoutParam, Integer.toString(serverConfig.getConnectionTimeout() * 1000));
		}

		if (serverConfig.isSsl()) {
			Security.addProvider(Security.getProvider("SunJSSE"));
		}

		switch (serverConfig.getProtocolOption()) {
			case IMAP:
				properties.setProperty(MAIL_STORE_PROTOCOL, "imap");

				if (serverConfig.isAuthLogin()) {
					properties.setProperty("mail.imap.auth.plain.disable", Boolean.TRUE.toString());
					properties.setProperty("mail.imap.auth.login.disable", Boolean.TRUE.toString());
				}

				if (serverConfig.isSsl()) {
					properties.setProperty(MAIL_STORE_PROTOCOL, "imaps");
					properties.setProperty("mail.imap.socketFactory.class", SSL_FACTORY_CLASS);
					if (port != Globals.DEFAULT_VALUE_INT) {
						properties.setProperty("mail.imap.socketFactory.port", Integer.toString(port));
					}
					properties.setProperty("mail.imap.starttls.enable", Boolean.TRUE.toString());
				}
				break;
			case SMTP:
				properties.setProperty(MAIL_STORE_PROTOCOL, "smtp");
				properties.setProperty(MAIL_TRANSPORT_PROTOCOL, "smtp");

				if (serverConfig.isAuthLogin()) {
					properties.setProperty("mail.smtp.auth", Boolean.TRUE.toString());
				}

				if (serverConfig.isSsl()) {
					properties.setProperty(MAIL_STORE_PROTOCOL, "smtps");
					properties.setProperty("mail.smtp.ssl.enable", Boolean.TRUE.toString());
					properties.setProperty("mail.smtp.socketFactory.class", SSL_FACTORY_CLASS);
					properties.setProperty("mail.smtp.socketFactory.fallback", Boolean.FALSE.toString());
					if (port != Globals.DEFAULT_VALUE_INT) {
						properties.setProperty("mail.smtp.socketFactory.port", Integer.toString(port));
					}
					properties.setProperty("mail.smtp.starttls.enable", Boolean.TRUE.toString());
				}
				break;
			case POP3:
				properties.setProperty(MAIL_STORE_PROTOCOL, "pop3");
				properties.setProperty(MAIL_TRANSPORT_PROTOCOL, "pop3");

				if (serverConfig.isSsl()) {
					properties.setProperty(MAIL_STORE_PROTOCOL, "pop3s");
					properties.setProperty(MAIL_TRANSPORT_PROTOCOL, "pop3s");
					properties.setProperty("mail.pop3.socketFactory.class", SSL_FACTORY_CLASS);
					if (port != 0) {
						properties.setProperty("mail.pop3.socketFactory.port", Integer.toString(port));
					}
					properties.setProperty("mail.pop3.disabletop", Boolean.TRUE.toString());
					properties.setProperty("mail.pop3.ssl.enable", Boolean.TRUE.toString());
					properties.setProperty("mail.pop3.useStartTLS", Boolean.TRUE.toString());
				}
				break;
			default:
				return new Properties();
		}
		this.configProxy(serverConfig.getProtocolOption(), properties);
		return properties;
	}

	/**
	 * <h3 class="en-US">Add proxy configure information to target Properties instance</h3>
	 * <h3 class="zh-CN">添加代理服务器信息到给定的Properties实例对象中</h3>
	 *
	 * @param mailProtocol <span class="en-US">Enumeration value of MailProtocol</span>
	 *                     <span class="zh-CN">电子邮件协议枚举值</span>
	 * @param properties   <span class="en-US">Given Properties instance</span>
	 *                     <span class="zh-CN">给定的Properties实例对象</span>
	 */
	private void configProxy(final MailProtocol mailProtocol, final Properties properties) {
		final String configPrefix;
		switch (mailProtocol) {
			case SMTP:
				configPrefix = "mail.smtp";
				break;
			case IMAP:
				configPrefix = "mail.imap";
				break;
			case POP3:
				configPrefix = "mail.pop3";
				break;
			default:
				return;
		}

		switch (this.proxyConfig.getProxyType()) {
			case HTTP:
				properties.setProperty(configPrefix + ".proxy.host", this.proxyConfig.getProxyAddress());
				if (this.proxyConfig.getProxyPort() != Globals.DEFAULT_VALUE_INT) {
					properties.setProperty(configPrefix + ".proxy.port",
							Integer.toString(this.proxyConfig.getProxyPort()));
				}
				if (StringUtils.notBlank(this.proxyConfig.getUserName())
						&& StringUtils.notBlank(this.proxyConfig.getPassword())) {
					properties.setProperty(configPrefix + ".proxy.user", this.proxyConfig.getUserName());
					properties.setProperty(configPrefix + ".proxy.password", this.proxyConfig.getPassword());
				}
				break;
			case SOCKS:
				properties.setProperty(configPrefix + ".socks.host", this.proxyConfig.getProxyAddress());
				properties.setProperty(configPrefix + ".socks.port", Integer.toString(this.proxyConfig.getProxyPort()));
				break;
		}
	}
}
