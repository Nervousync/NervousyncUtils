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

import jakarta.annotation.Nonnull;
import org.nervousync.builder.AbstractBuilder;
import org.nervousync.builder.ParentBuilder;
import org.nervousync.commons.Globals;
import org.nervousync.commons.RegexGlobals;
import org.nervousync.proxy.ProxyConfig;
import org.nervousync.enumerations.mail.MailProtocol;
import org.nervousync.exceptions.builder.BuilderException;
import org.nervousync.proxy.ProxyConfigBuilder;
import org.nervousync.utils.DateTimeUtils;
import org.nervousync.utils.FileUtils;
import org.nervousync.utils.ObjectUtils;
import org.nervousync.utils.StringUtils;

import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * <h2 class="en-US">Abstract mail configure builder for Generics Type</h2>
 * <p class="en-US">
 * The current abstract class is using to integrate to another builder
 * which configure contains mail configure information.
 * </p>
 * <h2 class="zh-CN">拥有父构造器的电子邮件配置信息抽象构造器</h2>
 * <p class="zh-CN">当前抽象构建器用于整合到包含邮件配置信息的其他配置构建器</p>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 31, 2022 16:27:18 $
 */
public final class MailConfigBuilder extends AbstractBuilder<MailConfig> implements ParentBuilder {

	/**
	 * <h2 class="en-US">Current mail configure information</h2>
	 * <h2 class="zh-CN">当前邮件配置信息</h2>
	 */
	private final MailConfig mailConfig;
	/**
	 * <h2 class="en-US">Configure information modified flag</h2>
	 * <h2 class="zh-CN">配置信息修改标记</h2>
	 */
	private boolean modified = Boolean.FALSE;

	/**
	 * <h3 class="en-US">Protected constructor for AbstractMailConfigBuilder</h3>
	 * <h3 class="zh-CN">AbstractMailConfigBuilder的构造函数</h3>
	 *
	 * @param parentBuilder <span class="en-US">Generics Type instance</span>
	 *                      <span class="zh-CN">泛型类实例对象</span>
	 * @param mailConfig    <span class="en-US">Mail configure information</span>
	 *                      <span class="zh-CN">邮件配置信息</span>
	 */
	private MailConfigBuilder(final ParentBuilder parentBuilder, final MailConfig mailConfig) {
		super(parentBuilder);
		this.mailConfig = (mailConfig == null) ? new MailConfig() : mailConfig;
	}

	/**
	 * <h3 class="en-US">Static method for create MailConfigBuilder instance by new mail configure information</h3>
	 * <h3 class="zh-CN">私有方法用于使用新的邮件配置信息创建邮件配置构造器实例对象</h3>
	 *
	 * @return <span class="en-US">Generated MailConfigBuilder instance</span>
	 * <span class="zh-CN">生成的邮件配置构造器实例对象</span>
	 */
	public static MailConfigBuilder newBuilder() {
		return newBuilder(new MailConfig());
	}

	/**
	 * <h3 class="en-US">Static method for create MailConfigBuilder instance by given mail configure</h3>
	 * <h3 class="zh-CN">私有方法用于使用给定的邮件配置信息创建邮件配置构造器实例对象</h3>
	 *
	 * @param mailConfig <span class="en-US">Mail configure information</span>
	 *                   <span class="zh-CN">邮件配置信息</span>
	 * @return <span class="en-US">Generated MailConfigBuilder instance</span>
	 * <span class="zh-CN">生成的邮件配置构造器实例对象</span>
	 */
	public static MailConfigBuilder newBuilder(final MailConfig mailConfig) {
		return newBuilder(null, mailConfig);
	}

	/**
	 * <h3 class="en-US">Static method for create MailConfigBuilder instance by new mail configure information</h3>
	 * <h3 class="zh-CN">私有方法用于使用新的邮件配置信息创建邮件配置构造器实例对象</h3>
	 *
	 * @return <span class="en-US">Generated MailConfigBuilder instance</span>
	 * <span class="zh-CN">生成的邮件配置构造器实例对象</span>
	 */
	public static MailConfigBuilder newBuilder(final ParentBuilder parentBuilder) {
		return newBuilder(parentBuilder, new MailConfig());
	}

	/**
	 * <h3 class="en-US">Static method for create MailConfigBuilder instance by given mail configure</h3>
	 * <h3 class="zh-CN">私有方法用于使用给定的邮件配置信息创建邮件配置构造器实例对象</h3>
	 *
	 * @param mailConfig <span class="en-US">Mail configure information</span>
	 *                   <span class="zh-CN">邮件配置信息</span>
	 * @return <span class="en-US">Generated MailConfigBuilder instance</span>
	 * <span class="zh-CN">生成的邮件配置构造器实例对象</span>
	 */
	public static MailConfigBuilder newBuilder(final ParentBuilder parentBuilder, final MailConfig mailConfig) {
		return new MailConfigBuilder(parentBuilder, mailConfig);
	}

	/**
	 * <h3 class="en-US">Configure authenticate information</h3>
	 * <h3 class="zh-CN">设置身份认证信息</h3>
	 *
	 * @param userName <span class="en-US">Mail account username</span>
	 *                 <span class="zh-CN">邮件账户用户名</span>
	 * @param password <span class="en-US">Mail account password</span>
	 *                 <span class="zh-CN">邮件账户密码</span>
	 * @return <span class="en-US">Current builder instance</span>
	 * <span class="zh-CN">当前构造器实例对象</span>
	 * @throws BuilderException the builder exception
	 *                          <span class="en-US">If username string not a valid e-mail address</span>
	 *                          <span class="zh-CN">当用户名不是合法的电子邮件地址时</span>
	 */
	public MailConfigBuilder authentication(final String userName, final String password)
			throws BuilderException {
		if (!StringUtils.matches(userName, RegexGlobals.EMAIL_ADDRESS)) {
			throw new BuilderException(0x0000000E0001L, "Username_Invalid_Mail_Error");
		}
		if (StringUtils.notBlank(userName) && !ObjectUtils.nullSafeEquals(this.mailConfig.getUserName(), userName)) {
			this.mailConfig.setUserName(userName);
			this.modified = Boolean.TRUE;
		}
		if (StringUtils.notBlank(password) && !ObjectUtils.nullSafeEquals(this.mailConfig.getPassword(), password)) {
			this.mailConfig.setPassword(password);
			this.modified = Boolean.TRUE;
		}
		return this;
	}

	/**
	 * <h3 class="en-US">Using current proxy configure information to create ProxyConfigBuilder instance</h3>
	 * <h3 class="zh-CN">使用当前的代理服务器配置信息生成代理服务器配置构建器实例对象</h3>
	 *
	 * @return <span class="en-US">ProxyConfigBuilder instance</span>
	 * <span class="zh-CN">代理服务器配置构建器实例对象</span>
	 */
	public ProxyConfigBuilder proxyConfig() {
		return new ProxyConfigBuilder(this, this.mailConfig.getProxyConfig());
	}

	/**
	 * <h3 class="en-US">Delete current proxy configure information</h3>
	 * <h3 class="zh-CN">删除代理服务器配置信息</h3>
	 *
	 * @return <span class="en-US">Current builder instance</span>
	 * <span class="zh-CN">当前构造器实例对象</span>
	 */
	public MailConfigBuilder removeProxyConfig() {
		if (this.mailConfig.getProxyConfig() != null) {
			this.mailConfig.setProxyConfig(null);
			this.modified = Boolean.TRUE;
		}
		return this;
	}

	/**
	 * <h3 class="en-US">Using current send server configure information to create ServerConfigBuilder instance</h3>
	 * <h3 class="zh-CN">使用当前的发送邮件服务器配置信息生成邮件服务器配置构建器实例对象</h3>
	 *
	 * @return <span class="en-US">ServerConfigBuilder instance</span>
	 * <span class="zh-CN">邮件服务器配置构建器实例对象</span>
	 */
	public ServerConfigBuilder sendConfig() {
		return Optional.ofNullable(this.mailConfig.getSendConfig())
				.map(serverConfig -> new ServerConfigBuilder(this, serverConfig))
				.orElse(new ServerConfigBuilder(this, new MailConfig.ServerConfig(Boolean.TRUE)));
	}

	/**
	 * <h3 class="en-US">Delete current send server configure information</h3>
	 * <h3 class="zh-CN">删除发送服务器配置信息</h3>
	 *
	 * @return <span class="en-US">Current builder instance</span>
	 * <span class="zh-CN">当前构造器实例对象</span>
	 */
	public MailConfigBuilder removeSendConfig() {
		if (this.mailConfig.getSendConfig() != null) {
			this.mailConfig.setSendConfig(null);
			this.modified = Boolean.TRUE;
		}
		return this;
	}

	/**
	 * <h3 class="en-US">Using current receive server configure information to create ServerConfigBuilder instance</h3>
	 * <h3 class="zh-CN">使用当前的接收邮件服务器配置信息生成邮件服务器配置构建器实例对象</h3>
	 *
	 * @return <span class="en-US">ServerConfigBuilder instance</span>
	 * <span class="zh-CN">邮件服务器配置构建器实例对象</span>
	 */
	public ServerConfigBuilder receiveConfig() {
		return Optional.ofNullable(this.mailConfig.getReceiveConfig())
				.map(serverConfig -> new ServerConfigBuilder(this, serverConfig))
				.orElse(new ServerConfigBuilder(this, new MailConfig.ServerConfig(Boolean.FALSE)));
	}

	/**
	 * <h3 class="en-US">Delete current receive server configure information</h3>
	 * <h3 class="zh-CN">删除接收服务器配置信息</h3>
	 *
	 * @return <span class="en-US">Current builder instance</span>
	 * <span class="zh-CN">当前构造器实例对象</span>
	 */
	public MailConfigBuilder removeReceiveConfig() {
		if (this.mailConfig.getReceiveConfig() != null) {
			this.mailConfig.setReceiveConfig(null);
			this.modified = Boolean.TRUE;
		}
		return this;
	}

	/**
	 * <h3 class="en-US">Configure save path of mail attachment files</h3>
	 * <h3 class="zh-CN">设置电子邮件附件的保存地址</h3>
	 *
	 * @param storagePath <span class="en-US">Local save path</span>
	 *                    <span class="zh-CN">本地保存地址</span>
	 * @return <span class="en-US">ServerConfigBuilder instance</span>
	 * <span class="zh-CN">邮件服务器配置构建器实例对象</span>
	 * @throws BuilderException <span class="en-US">If storage path is empty string or folder not exists</span>
	 *                          <span class="zh-CN">如果本地保存地址为空字符串或目录不存在</span>
	 */
	public MailConfigBuilder storagePath(final String storagePath) throws BuilderException {
		if (StringUtils.isEmpty(storagePath) || !FileUtils.makeDir(storagePath)) {
			throw new BuilderException(0x0000000E0002L, "Storage_Path_NotFound_Mail_Error");
		}
		if (ObjectUtils.nullSafeEquals(this.mailConfig.getStoragePath(), storagePath)) {
			return this;
		}
		this.mailConfig.setStoragePath(storagePath);
		this.modified = Boolean.TRUE;
		return this;
	}

	/**
	 * <h3 class="en-US">Configure the x509 certificate and private key for mail signature</h3>
	 * <h3 class="zh-CN">设置用于电子邮件签名及验签的x509证书及私钥</h3>
	 *
	 * @param x509Certificate <span class="en-US">x509 certificate using for verify signature</span>
	 *                        <span class="zh-CN">x509证书，用于验证电子签名</span>
	 * @param privateKey      <span class="en-US">Private key instance using for generate signature</span>
	 *                        <span class="zh-CN">私钥对象实例，用于生成电子签名</span>
	 * @return <span class="en-US">ServerConfigBuilder instance</span>
	 * <span class="zh-CN">邮件服务器配置构建器实例对象</span>
	 */
	public MailConfigBuilder signer(final X509Certificate x509Certificate, final PrivateKey privateKey) {
		if (x509Certificate != null && privateKey != null) {
			try {
				String certData = StringUtils.base64Encode(x509Certificate.getEncoded());
				String pkData = StringUtils.base64Encode(privateKey.getEncoded());
				if (ObjectUtils.nullSafeEquals(this.mailConfig.getCertificate(), certData)
						&& ObjectUtils.nullSafeEquals(this.mailConfig.getPrivateKey(), pkData)) {
					return this;
				}
				this.mailConfig.setCertificate(certData);
				this.mailConfig.setPrivateKey(pkData);
				this.modified = Boolean.TRUE;
			} catch (CertificateEncodingException e) {
				if (StringUtils.notBlank(this.mailConfig.getCertificate())
						|| StringUtils.notBlank(this.mailConfig.getPrivateKey())) {
					this.modified = Boolean.TRUE;
				}
				this.mailConfig.setCertificate(Globals.DEFAULT_VALUE_STRING);
				this.mailConfig.setPrivateKey(Globals.DEFAULT_VALUE_STRING);
			}
		}
		return this;
	}

	@Override
	public void confirm(final Object object) {
		Optional.ofNullable(object).ifPresent(config -> {
			if (config instanceof ProxyConfig) {
				if (this.mailConfig.getProxyConfig().getLastModified() != ((ProxyConfig) config).getLastModified()) {
					this.modified = Boolean.TRUE;
					this.mailConfig.setProxyConfig((ProxyConfig) config);
				}
			} else if (config instanceof MailConfig.ServerConfig) {
				MailConfig.ServerConfig serverConfig = (MailConfig.ServerConfig) config;
				if (serverConfig.isSendConfig()) {
					if (this.mailConfig.getSendConfig() == null
							|| this.mailConfig.getSendConfig().getLastModified() != serverConfig.getLastModified()) {
						this.modified = Boolean.TRUE;
						this.mailConfig.setSendConfig(serverConfig);
					}
				} else {
					if (this.mailConfig.getReceiveConfig() == null
							|| this.mailConfig.getReceiveConfig().getLastModified() != serverConfig.getLastModified()) {
						this.modified = Boolean.TRUE;
						this.mailConfig.setReceiveConfig(serverConfig);
					}
				}
			}
		});
	}

	@Override
	public MailConfig confirm() {
		if (this.modified) {
			this.mailConfig.setLastModified(DateTimeUtils.currentUTCTimeMillis());
		}
		return this.mailConfig;
	}

	/**
	 * <h2 class="en-US">Mail server configure builder</h2>
	 * <h2 class="zh-CN">电子邮件服务器配置信息抽象构造器</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0.0 $ $Date: Jul 31, 2022 16:35:16 $
	 */
	public static final class ServerConfigBuilder extends AbstractBuilder<MailConfig.ServerConfig> {

		/**
		 * <span class="en-US">Server configure information</span>
		 * <span class="zh-CN">服务器配置</span>
		 */
		private final MailConfig.ServerConfig serverConfig;
		/**
		 * <h2 class="en-US">Configure information modified flag</h2>
		 * <h2 class="zh-CN">配置信息修改标记</h2>
		 */
		private boolean modified = Boolean.FALSE;

		/**
		 * <h3 class="en-US">Private constructor for ServerConfigBuilder</h3>
		 * <h3 class="zh-CN">ServerConfigBuilder的私有构造函数</h3>
		 *
		 * @param parentBuilder <span class="en-US">Mail configure builder instance</span>
		 *                      <span class="zh-CN">电子邮件配置构造器实例</span>
		 * @param serverConfig  <span class="en-US">Server configure information</span>
		 *                      <span class="zh-CN">服务器配置</span>
		 */
		private ServerConfigBuilder(final ParentBuilder parentBuilder,
		                            @Nonnull final MailConfig.ServerConfig serverConfig) {
			super(parentBuilder);
			this.serverConfig = serverConfig;
		}

		/**
		 * <h3 class="en-US">Configure host server information</h3>
		 * <h3 class="zh-CN">设置服务器信息</h3>
		 *
		 * @param hostAddress <span class="en-US">Mail server domain name</span>
		 *                    <span class="zh-CN">邮件服务器域名</span>
		 * @param hostPort    <span class="en-US">Mail server port</span>
		 *                    <span class="zh-CN">邮件服务器端口号</span>
		 * @return <span class="en-US">ServerConfigBuilder instance</span>
		 * <span class="zh-CN">邮件服务器配置构建器实例对象</span>
		 */
		public ServerConfigBuilder configHost(final String hostAddress, final int hostPort) {
			if (ObjectUtils.nullSafeEquals(this.serverConfig.getHostName(), hostAddress)
					&& this.serverConfig.getHostPort() == hostPort) {
				return this;
			}
			this.serverConfig.setHostName(hostAddress);
			if (hostPort > 0) {
				this.serverConfig.setHostPort(hostPort);
			}
			this.modified = Boolean.TRUE;
			return this;
		}

		/**
		 * <h3 class="en-US">Configure using secure connection to host server</h3>
		 * <h3 class="zh-CN">设置使用安全连接到邮件服务器</h3>
		 *
		 * @param useSSL <span class="en-US">Using secure connection to host server</span>
		 *               <span class="zh-CN">使用安全连接到邮件服务器</span>
		 * @return <span class="en-US">ServerConfigBuilder instance</span>
		 * <span class="zh-CN">邮件服务器配置构建器实例对象</span>
		 */
		public ServerConfigBuilder useSSL(final boolean useSSL) {
			if (ObjectUtils.nullSafeEquals(this.serverConfig.isSsl(), useSSL)) {
				return this;
			}
			this.serverConfig.setSsl(useSSL);
			this.modified = Boolean.TRUE;
			return this;
		}

		/**
		 * <h3 class="en-US">Configure using secure connection to host server</h3>
		 * <h3 class="zh-CN">设置使用安全连接到邮件服务器</h3>
		 *
		 * @param authLogin the auth login
		 *                  <span class="en-US">Host server authenticate login</span>
		 *                  <span class="zh-CN">邮件服务器需要身份验证</span>
		 * @return <span class="en-US">ServerConfigBuilder instance</span>
		 * <span class="zh-CN">邮件服务器配置构建器实例对象</span>
		 */
		public ServerConfigBuilder authLogin(final boolean authLogin) {
			if (ObjectUtils.nullSafeEquals(this.serverConfig.isAuthLogin(), authLogin)) {
				return this;
			}
			this.serverConfig.setAuthLogin(authLogin);
			this.modified = Boolean.TRUE;
			return this;
		}

		/**
		 * <h3 class="en-US">Configure mail server protocol</h3>
		 * <h3 class="zh-CN">设置邮件服务器协议</h3>
		 *
		 * @param protocolOption <span class="en-US">Mail server protocol</span>
		 *                       <span class="zh-CN">邮件服务器协议</span>
		 * @return <span class="en-US">ServerConfigBuilder instance</span>
		 * <span class="zh-CN">邮件服务器配置构建器实例对象</span>
		 */
		public ServerConfigBuilder mailProtocol(final MailProtocol protocolOption) {
			if (MailProtocol.UNKNOWN.equals(protocolOption)
					|| ObjectUtils.nullSafeEquals(this.serverConfig.getProtocolOption(), protocolOption)) {
				return this;
			}
			this.serverConfig.setProtocolOption(protocolOption);
			this.modified = Boolean.TRUE;
			return this;
		}

		/**
		 * <h3 class="en-US">Configure connection timeout (Unit: seconds)</h3>
		 * <h3 class="zh-CN">设置连接超时时间（单位：秒）</h3>
		 *
		 * @param connectionTimeout <span class="en-US">Connection timeout(Unit: seconds)</span>
		 *                          <span class="zh-CN">连接超时时间（单位：秒）</span>
		 * @return <span class="en-US">ServerConfigBuilder instance</span>
		 * <span class="zh-CN">邮件服务器配置构建器实例对象</span>
		 */
		public ServerConfigBuilder connectionTimeout(final int connectionTimeout) {
			if (connectionTimeout <= 0 || this.serverConfig.getConnectionTimeout() == connectionTimeout) {
				return this;
			}
			this.serverConfig.setConnectionTimeout(connectionTimeout);
			this.modified = Boolean.TRUE;
			return this;
		}

		/**
		 * <h3 class="en-US">Configure process timeout (Unit: seconds)</h3>
		 * <h3 class="zh-CN">设置操作超时时间（单位：秒）</h3>
		 *
		 * @param processTimeout <span class="en-US">Process timeout(Unit: seconds)</span>
		 *                       <span class="zh-CN">操作超时时间（单位：秒）</span>
		 * @return <span class="en-US">ServerConfigBuilder instance</span>
		 * <span class="zh-CN">邮件服务器配置构建器实例对象</span>
		 */
		public ServerConfigBuilder processTimeout(final int processTimeout) {
			if (processTimeout <= 0 || this.serverConfig.getProcessTimeout() == processTimeout) {
				return this;
			}
			this.serverConfig.setProcessTimeout(processTimeout);
			this.modified = Boolean.TRUE;
			return this;
		}

		@Override
		public MailConfig.ServerConfig confirm() throws BuilderException {
			if (StringUtils.isEmpty(this.serverConfig.getHostName())) {
				throw new BuilderException(0x0000000E0003L, "Host_Address_Unknown_Mail_Error");
			}
			if (MailProtocol.UNKNOWN.equals(this.serverConfig.getProtocolOption())) {
				throw new BuilderException(0x0000000E0004L, "Protocol_Unknown_Mail_Error");
			}
			if (this.modified) {
				this.serverConfig.setLastModified(DateTimeUtils.currentUTCTimeMillis());
			}
			return this.serverConfig;
		}
	}

}
