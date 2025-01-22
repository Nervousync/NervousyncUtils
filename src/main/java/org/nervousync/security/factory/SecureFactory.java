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
package org.nervousync.security.factory;

import jakarta.annotation.Nonnull;
import org.nervousync.commons.Globals;
import org.nervousync.configs.ConfigureManager;
import org.nervousync.exceptions.crypto.CryptoException;
import org.nervousync.security.api.SecureAdapter;
import org.nervousync.security.config.AbstractConfig;
import org.nervousync.security.config.FactoryConfig;
import org.nervousync.security.config.SecureConfig;
import org.nervousync.security.config.SecureSettings;
import org.nervousync.utils.*;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * <h2 class="en-US">Secure factory instance</h2>
 * <p class="en-US">
 * Running in singleton mode. Using for protect password in any configuring files.
 * Supported algorithm: RSA1024/RSA2048/SM2/AES128/AES192/AES256/DES/3DES/SM4
 * </p>
 * <h2 class="zh-CN">安全配置信息定义</h2>
 * <p class="zh-CN">使用单例模式运行。用于在任何配置文件中保护密码。支持的算法：RSA1024/RSA2048/SM2/AES128/AES192/AES256/DES/3DES/SM4</p>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2012 12:33:56 $
 */
public final class SecureFactory {
	/**
	 * <span class="en-US">Multilingual supported logger instance</span>
	 * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(SecureFactory.class);
	/**
	 * <span class="en-US">Security configuration information storage directory</span>
	 * <span class="zh-CN">安全配置信息存储目录</span>
	 */
	private static final String DEFAULT_SECURE_FOLDER_PATH = Globals.DEFAULT_PAGE_SEPARATOR + ".secure";
	/**
	 * <span class="en-US">Security factory configuration information storage path</span>
	 * <span class="zh-CN">安全工厂配置信息存储地址</span>
	 */
	private static final String DEFAULT_SECURE_FACTORY_CONFIG =
			DEFAULT_SECURE_FOLDER_PATH + Globals.DEFAULT_PAGE_SEPARATOR + "secure_factory.xml";
	/**
	 * <span class="en-US">System default security configuration name</span>
	 * <span class="zh-CN">系统默认安全配置名称</span>
	 */
	public static final String SYSTEM_SECURE_NAME = "Nervousync_Secure";
	/**
	 * <span class="en-US">Default certificate alias</span>
	 * <span class="zh-CN">默认证书别名</span>
	 */
	private static final String SECURE_CERTIFICATE_ALIAS = "NSYC";
	/**
	 * <span class="en-US">Default certificate password</span>
	 * <span class="zh-CN">默认证书库密码</span>
	 */
	private static final String SECURE_CERTIFICATE_PASSWORD = "ns0528AO";
	/**
	 * <span class="en-US">Secure factory singleton instance object</span>
	 * <span class="zh-CN">安全工厂全局唯一实例对象</span>
	 */
	private static SecureFactory INSTANCE = null;
	/**
	 * <span class="en-US">Factory secure node</span>
	 * <span class="zh-CN">工厂安全节点</span>
	 */
	private static final SecureNode FACTORY_NODE;
	/**
	 * <span class="en-US">Registered secure factory node mapping table</span>
	 * <span class="zh-CN">已注册的安全节点映射表</span>
	 */
	private final Map<String, SecureNode> registeredNodes;

	static {
		FileUtils.makeDir(SystemUtils.USER_HOME + DEFAULT_SECURE_FOLDER_PATH);
		String factoryPath = SystemUtils.USER_HOME + DEFAULT_SECURE_FACTORY_CONFIG;
		FactoryConfig factoryConfig = Optional.of(FileUtils.readFile(factoryPath))
				.filter(StringUtils::notBlank)
				.map(string -> StringUtils.stringToObject(string, FactoryConfig.class))
				.orElse(null);
		if (factoryConfig == null) {
			factoryConfig = new FactoryConfig();
			factoryConfig.setSecureAlgorithm(SecureAlgorithm.RSA1024);
			factoryConfig.setSecureKey(StringUtils.base64Encode(generate(SecureAlgorithm.RSA1024)));
			FileUtils.saveFile(SystemUtils.USER_HOME + DEFAULT_SECURE_FACTORY_CONFIG, factoryConfig.toXML(Boolean.TRUE));
		}
		FACTORY_NODE = new SecureNode(factoryConfig);
		initialize(Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Private constructor method for SecureFactory</h3>
	 * <h3 class="zh-CN">安全工厂的私有构造方法</h3>
	 */
	private SecureFactory() {
		this.registeredNodes = new HashMap<>();
		Optional.ofNullable(ConfigureManager.getInstance())
				.map(configureManager -> configureManager.readConfigure(SecureSettings.class))
				.ifPresent(secureSettings -> {
					Optional.ofNullable(secureSettings.getSystemSecure()).ifPresent(this::register);
					Optional.ofNullable(secureSettings.getCustomSecures())
							.ifPresent(customSecures -> customSecures.forEach(this::register));
				});
	}

	/**
	 * <h3 class="en-US">Configure root secure node using given secure config</h3>
	 * <h3 class="zh-CN">使用给定的安全配置信息设置安全工厂的根安全节点</h3>
	 */
	public static void initialize(final boolean reload) {
		if (INSTANCE == null || reload) {
			if (INSTANCE != null && LOGGER.isDebugEnabled()) {
				LOGGER.debug("Override_Factory_Config_Debug");
			}
			INSTANCE = new SecureFactory();
		}
	}

	/**
	 * <h3 class="en-US">Removes the given security name from the configuration information and unregisters it</h3>
	 * <h3 class="zh-CN">将给定的安全名称从配置信息中移除并取消注册</h3>
	 *
	 * @param secureName <span class="en-US">Secure name</span>
	 *                   <span class="zh-CN">安全名称</span>
	 * @return <span class="en-US">Operate result</span>
	 * <span class="zh-CN">执行结果</span>
	 */
	public static boolean removeConfig(final String secureName) {
		if (StringUtils.isEmpty(secureName)
				|| ObjectUtils.nullSafeEquals(SYSTEM_SECURE_NAME, secureName)) {
			return Boolean.FALSE;
		}

		ConfigureManager configureManager = ConfigureManager.getInstance();
		if (configureManager == null) {
			return Boolean.FALSE;
		}

		return Optional.ofNullable(configureManager.readConfigure(SecureSettings.class))
				.map(secureSettings -> {
					List<SecureConfig> customSecures = secureSettings.getCustomSecures();
					if (customSecures.removeIf(existConfig ->
							ObjectUtils.nullSafeEquals(existConfig.getSecureName(), secureName))) {
						secureSettings.setCustomSecures(customSecures);
						return configureManager.saveConfigure(secureSettings);
					}
					return Boolean.TRUE;
				})
				.orElse(Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Generate and register secure configure information using given secure algorithm</h3>
	 * <h3 class="zh-CN">使用给定的安全算法生成并注册安全配置信息</h3>
	 *
	 * @param secureAlgorithm <span class="en-US">Secure algorithm</span>
	 *                        <span class="zh-CN">安全算法</span>
	 * @return <span class="en-US">Operate result</span>
	 * <span class="zh-CN">执行结果</span>
	 */
	public static boolean systemConfig(final SecureAlgorithm secureAlgorithm) {
		if (INSTANCE == null) {
			return Boolean.FALSE;
		}
		return Optional.ofNullable(newConfig(SYSTEM_SECURE_NAME, secureAlgorithm))
				.filter(SecureFactory::saveSetting)
				.map(secureConfig -> {
					INSTANCE.register(secureConfig);
					return Boolean.TRUE;
				})
				.orElse(Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Generate and register secure configure information using given secure algorithm</h3>
	 * <h3 class="zh-CN">使用给定的安全算法生成并注册安全配置信息</h3>
	 *
	 * @param secureName      <span class="en-US">Secure name</span>
	 *                        <span class="zh-CN">安全名称</span>
	 * @param secureAlgorithm <span class="en-US">Secure algorithm</span>
	 *                        <span class="zh-CN">安全算法</span>
	 * @return <span class="en-US">Operate result</span>
	 * <span class="zh-CN">执行结果</span>
	 */
	public static boolean initConfig(final String secureName, final SecureAlgorithm secureAlgorithm) {
		if (INSTANCE == null || StringUtils.isEmpty(secureName)
				|| ObjectUtils.nullSafeEquals(SYSTEM_SECURE_NAME, secureName)) {
			return Boolean.FALSE;
		}
		return Optional.ofNullable(newConfig(secureName, secureAlgorithm))
				.filter(SecureFactory::saveSetting)
				.map(secureConfig -> {
					INSTANCE.register(secureConfig);
					return Boolean.TRUE;
				})
				.orElse(Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Check given secure name was registered</h3>
	 * <h3 class="zh-CN">检查给定的安全名称注册状态</h3>
	 *
	 * @param secureName <span class="en-US">Secure name</span>
	 *                   <span class="zh-CN">安全名称</span>
	 * @return the boolean
	 */
	public static boolean registeredConfig(final String secureName) {
		if (INSTANCE == null || StringUtils.isEmpty(secureName)) {
			return Boolean.FALSE;
		}
		return INSTANCE.registeredNodes.containsKey(secureName);
	}

	/**
	 * <h3 class="en-US">Encrypt data content using given secure name</h3>
	 * <h3 class="zh-CN">使用给定的安全名称加密密码信息</h3>
	 *
	 * @param secureName  <span class="en-US">New secure name</span>
	 *                    <span class="zh-CN">新安全配置名称</span>
	 * @param dataContent <span class="en-US">Password data</span>
	 *                    <span class="zh-CN">密码信息</span>
	 * @return <span class="en-US">Encrypted password data</span>
	 * <span class="zh-CN">加密后的密码信息</span>
	 */
	public static String encrypt(final String secureName, final String dataContent) {
		return Optional.ofNullable(INSTANCE)
				.map(secureFactory -> secureFactory.processData(secureName, dataContent, Boolean.TRUE))
				.orElse(dataContent);
	}

	/**
	 * <h3 class="en-US">Decrypt data content using given secure name</h3>
	 * <h3 class="zh-CN">使用给定的安全名称解密密码信息</h3>
	 *
	 * @param secureName  <span class="en-US">New secure name</span>
	 *                    <span class="zh-CN">新安全配置名称</span>
	 * @param dataContent <span class="en-US">Password data</span>
	 *                    <span class="zh-CN">密码信息</span>
	 * @return <span class="en-US">Decrypted password data</span>
	 * <span class="zh-CN">解密后的密码信息</span>
	 */
	public static String decrypt(final String secureName, final String dataContent) {
		return Optional.ofNullable(INSTANCE)
				.map(secureFactory -> secureFactory.processData(secureName, dataContent, Boolean.FALSE))
				.orElse(dataContent);
	}

	/**
	 * <h3 class="en-US">Register secure config by given secure name and configure information instance</h3>
	 * <h3 class="zh-CN">将给定的安全名称和安全配置信息实例注册到安全工厂</h3>
	 *
	 * @param secureConfig <span class="en-US">Secure config information</span>
	 *                     <span class="zh-CN">安全配置信息</span>
	 */
	private void register(@Nonnull final SecureConfig secureConfig) {
		if (this.registeredNodes.containsKey(secureConfig.getSecureName()) && LOGGER.isDebugEnabled()) {
			LOGGER.debug("Security_Override_Config", secureConfig.getSecureName());
		}
		this.registeredNodes.put(secureConfig.getSecureName(), new SecureNode(secureConfig));
	}

	/**
	 * <h3 class="en-US">Save the given security configuration information in a configuration file</h3>
	 * <h3 class="zh-CN">将给定的安全配置信息保存在配置文件中</h3>
	 *
	 * @param secureConfig <span class="en-US">Secure config information</span>
	 *                     <span class="zh-CN">安全配置信息</span>
	 * @return <span class="en-US">Save result</span>
	 * <span class="zh-CN">保存结果</span>
	 */
	private static synchronized boolean saveSetting(@Nonnull final SecureConfig secureConfig) {
		if (StringUtils.isEmpty(secureConfig.getSecureName())) {
			return Boolean.FALSE;
		}
		ConfigureManager configureManager = ConfigureManager.getInstance();
		if (configureManager == null) {
			return Boolean.FALSE;
		}
		SecureSettings secureSettings = configureManager.readConfigure(SecureSettings.class);
		if (secureSettings == null) {
			secureSettings = new SecureSettings();
		}
		if (ObjectUtils.nullSafeEquals(SYSTEM_SECURE_NAME, secureConfig.getSecureName())) {
			secureSettings.setSystemSecure(secureConfig);
		} else {
			List<SecureConfig> customSecures = secureSettings.getCustomSecures();
			final AtomicBoolean needProcess = new AtomicBoolean(Boolean.TRUE);
			customSecures.replaceAll(existConfig -> {
				if (ObjectUtils.nullSafeEquals(existConfig.getSecureName(), secureConfig.getSecureName())) {
					needProcess.set(Boolean.FALSE);
					return secureConfig;
				}
				return existConfig;
			});
			if (needProcess.get()) {
				customSecures.add(secureConfig);
			}
			secureSettings.setCustomSecures(customSecures);
		}
		return configureManager.saveConfigure(secureSettings);
	}

	/**
	 * <h3 class="en-US">Process data content using given secure name</h3>
	 * <h3 class="zh-CN">使用给定的安全名称处理信息</h3>
	 *
	 * @param secureName  <span class="en-US">Secure name</span>
	 *                    <span class="zh-CN">安全配置名称</span>
	 * @param dataContent <span class="en-US">Information that needs to be processed</span>
	 *                    <span class="zh-CN">需要处理的信息</span>
	 * @param encrypt     <span class="en-US">Encrypt/Decrypt data</span>
	 *                    <span class="zh-CN">加密/解密信息</span>
	 * @return <span class="en-US">Decrypted password data</span>
	 * <span class="zh-CN">解密后的密码信息</span>
	 */
	private String processData(final String secureName, final String dataContent, final boolean encrypt) {
		if (StringUtils.isEmpty(secureName) || StringUtils.isEmpty(dataContent)) {
			return dataContent;
		}
		String secName = StringUtils.isEmpty(secureName) ? SYSTEM_SECURE_NAME : secureName;
		return Optional.ofNullable(this.registeredNodes.get(secName))
				.map(secureNode -> secureNode.initCryptor(encrypt))
				.map(secureAdapter -> {
					String returnValue;
					try {
						byte[] dataBytes =
								encrypt ? ConvertUtils.toByteArray(dataContent) : StringUtils.base64Decode(dataContent);
						byte[] resultBytes = secureAdapter.finish(dataBytes);
						returnValue =
								encrypt ? StringUtils.base64Encode(resultBytes) : ConvertUtils.toString(resultBytes);
					} catch (CryptoException e) {
						LOGGER.error(encrypt ? "Encrypt_Data_Error" : "Decrypt_Data_Error");
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Stack_Message_Error", e);
						}
						returnValue = dataContent;
					}
					return returnValue;
				})
				.orElse(dataContent);
	}

	/**
	 * <h3 class="en-US">Generate and register secure configure information using given secure algorithm and secure key data bytes</h3>
	 * <h3 class="zh-CN">使用给定的安全算法、安全密钥字节数组生成并注册安全配置信息</h3>
	 *
	 * @param secureName <span class="en-US">Secure name</span>
	 *                   <span class="zh-CN">安全名称</span>
	 * @param algorithm  <span class="en-US">Secure algorithm</span>
	 *                   <span class="zh-CN">安全算法</span>
	 * @return <span class="en-US">Operate result</span>
	 * <span class="zh-CN">执行结果</span>
	 */
	private static SecureConfig newConfig(@Nonnull final String secureName, @Nonnull final SecureAlgorithm algorithm) {
		if (StringUtils.isEmpty(secureName)) {
			LOGGER.error("Secure_Name_Empty_Error");
			return null;
		}
		final byte[] secureKey = generate(algorithm);
		if (secureKey.length == 0) {
			LOGGER.error("Key_Bytes_Empty_Error");
			return null;
		}
		SecureConfig secureConfig = new SecureConfig();
		secureConfig.setSecureName(secureName);
		secureConfig.setSecureAlgorithm(algorithm);
		secureConfig.setSecureKey(StringUtils.base64Encode(initKey(secureKey, Boolean.TRUE)));
		return secureConfig;
	}

	/**
	 * <h3 class="en-US">Initialize key bytes</h3>
	 * <h3 class="zh-CN">初始化加密密钥数据</h3>
	 *
	 * @param dataBytes <span class="en-US">key bytes</span>
	 *                  <span class="zh-CN">加密密钥数据</span>
	 * @param encrypt   <span class="en-US">Encrypt status</span>
	 *                  <span class="zh-CN">加密密钥数据</span>
	 * @return <span class="en-US">Initialized data bytes</span>
	 * <span class="zh-CN">初始化的数据</span>
	 */
	private static byte[] initKey(@Nonnull final byte[] dataBytes, final boolean encrypt) {
		return Optional.ofNullable(FACTORY_NODE)
				.filter(SecureNode::isInitialized)
				.map(factoryNode -> factoryNode.initCryptor(encrypt))
				.map(secureAdapter -> {
					try {
						return secureAdapter.finish(dataBytes);
					} catch (Exception e) {
						return dataBytes;
					}
				})
				.filter(keyBytes -> keyBytes.length > 0)
				.orElse(dataBytes);
	}

	/**
	 * <h3 class="en-US">Generate secure key by given secure algorithm</h3>
	 * <h3 class="zh-CN">使用给定的安全算法生成安全密钥</h3>
	 *
	 * @param secureAlgorithm <span class="en-US">Secure algorithm</span>
	 *                        <span class="zh-CN">安全算法</span>
	 * @return <span class="en-US">Generated key data bytes</span>
	 * <span class="zh-CN">生成的安全密钥数据</span>
	 */
	private static byte[] generate(final SecureAlgorithm secureAlgorithm) {
		switch (secureAlgorithm) {
			case RSA1024:
				return convertKeyPair(SecurityUtils.RSAKeyPair(1024), "SHA256withRSA");
			case RSA2048:
				return convertKeyPair(SecurityUtils.RSAKeyPair(2048), "SHA256withRSA");
			case SM2:
				return convertKeyPair(SecurityUtils.SM2KeyPair(), "SM3withSM2");
			case AES128:
				return SecurityUtils.AES128Key();
			case AES192:
				return SecurityUtils.AES192Key();
			case AES256:
				return SecurityUtils.AES256Key();
			case DES:
				return SecurityUtils.DESKey();
			case TRIPLE_DES:
				return SecurityUtils.TripleDESKey();
			case SM4:
				return SecurityUtils.SM4Key();
			default:
				return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Convert asymmetric key pair instance to secure key data bytes, using given signature algorithm</h3>
	 * <h3 class="zh-CN">使用给定的签名算法将非对称密钥对实例对象转换为安全密钥数据</h3>
	 *
	 * @param keyPair       <span class="en-US">Asymmetric key pair instance</span>
	 *                      <span class="zh-CN">非对称密钥对实例对象</span>
	 * @param signAlgorithm <span class="en-US">Signature algorithm</span>
	 *                      <span class="zh-CN">签名算法</span>
	 * @return <span class="en-US">Generated key data bytes</span>
	 * <span class="zh-CN">生成的安全密钥数据</span>
	 */
	private static byte[] convertKeyPair(final KeyPair keyPair, final String signAlgorithm) {
		long currentTime = DateTimeUtils.currentTimeMillis();
		return CertificateUtils.PKCS12(keyPair, currentTime, new Date(currentTime),
				new Date(currentTime + 365 * 24 * 60 * 60 * 1000L), SECURE_CERTIFICATE_ALIAS,
				SECURE_CERTIFICATE_ALIAS, SECURE_CERTIFICATE_PASSWORD, null, signAlgorithm);
	}

	/**
	 * <h2 class="en-US">Secure Node</h2>
	 * <h2 class="zh-CN">安全配置信息定义</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2012 12:38:45 $
	 */
	private static final class SecureNode {
		/**
		 * <span class="en-US">Node initialize status</span>
		 * <span class="zh-CN">节点初始化状态</span>
		 */
		private final boolean initialized;
		/**
		 * <span class="en-US">Secure algorithm</span>
		 * <span class="zh-CN">安全算法</span>
		 */
		private final SecureAlgorithm secureAlgorithm;
		/**
		 * <span class="en-US">Secure key data bytes</span>
		 * <span class="zh-CN">安全密钥数据</span>
		 */
		private final byte[] keyBytes;
		/**
		 * <span class="en-US">Asymmetric private key</span>
		 * <span class="zh-CN">非对称加密私钥</span>
		 */
		private final PrivateKey privateKey;
		/**
		 * <span class="en-US">Asymmetric public key</span>
		 * <span class="zh-CN">非对称加密公钥</span>
		 */
		private final PublicKey publicKey;

		/**
		 * <h3 class="en-US">Constructor for SecureNode</h3>
		 * <h3 class="zh-CN">安全节点构造方法</h3>
		 *
		 * @param secureConfig <span class="en-US">Secure config information</span>
		 *                     <span class="zh-CN">安全配置信息</span>
		 */
		private SecureNode(@Nonnull final AbstractConfig secureConfig) {
			final byte[] keyBytes =
					SecureFactory.initKey(StringUtils.base64Decode(secureConfig.getSecureKey()), Boolean.FALSE);
			this.secureAlgorithm = secureConfig.getSecureAlgorithm();
			switch (this.secureAlgorithm) {
				case RSA1024:
				case RSA2048:
				case SM2:
					this.keyBytes = keyBytes;
					KeyStore keyStore = CertificateUtils.loadKeyStore(keyBytes, SECURE_CERTIFICATE_PASSWORD);
					if (keyStore == null) {
						this.initialized = Boolean.FALSE;
						this.privateKey = null;
						this.publicKey = null;
					} else {
						this.publicKey =
								Optional.ofNullable(CertificateUtils.x509(keyStore, SECURE_CERTIFICATE_ALIAS))
										.map(Certificate::getPublicKey)
										.orElse(null);
						this.privateKey = CertificateUtils.privateKey(keyStore, SECURE_CERTIFICATE_ALIAS,
								SECURE_CERTIFICATE_PASSWORD);
						this.initialized = (this.publicKey != null && this.privateKey != null);
					}
					break;
				case AES128:
				case AES192:
				case AES256:
				case DES:
				case TRIPLE_DES:
				case SM4:
					this.initialized = Boolean.TRUE;
					this.keyBytes = keyBytes;
					this.privateKey = null;
					this.publicKey = null;
					break;
				default:
					this.initialized = Boolean.FALSE;
					this.keyBytes = null;
					this.privateKey = null;
					this.publicKey = null;
					break;
			}
		}

		/**
		 * <h3 class="en-US">Initialize secure adapter</h3>
		 * <h3 class="zh-CN">初始化加密解密适配器</h3>
		 *
		 * @param encrypt <span class="en-US">Encrypt status</span>
		 *                <span class="zh-CN">加密状态</span>
		 * @return <span class="en-US">Initialized adapter instance</span>
		 * <span class="zh-CN">初始化的适配器实例对象</span>
		 */
		private SecureAdapter initCryptor(boolean encrypt) {
			SecureAdapter secureAdapter = null;
			if (this.initialized) {
				try {
					switch (this.secureAlgorithm) {
						case RSA1024:
						case RSA2048:
							secureAdapter = encrypt ? SecurityUtils.RSAEncryptor(this.publicKey)
									: SecurityUtils.RSADecryptor(this.privateKey);
							break;
						case SM2:
							secureAdapter = encrypt ? SecurityUtils.SM2Encryptor(this.publicKey)
									: SecurityUtils.SM2Decryptor(this.privateKey);
							break;
						case AES128:
						case AES192:
						case AES256:
							secureAdapter = encrypt ? SecurityUtils.AESEncryptor(this.keyBytes)
									: SecurityUtils.AESDecryptor(this.keyBytes);
							break;
						case DES:
							secureAdapter = encrypt ? SecurityUtils.DESEncryptor(this.keyBytes)
									: SecurityUtils.DESDecryptor(this.keyBytes);
							break;
						case TRIPLE_DES:
							secureAdapter = encrypt ? SecurityUtils.TripleDESEncryptor(this.keyBytes)
									: SecurityUtils.TripleDESDecryptor(this.keyBytes);
							break;
						case SM4:
							secureAdapter = encrypt ? SecurityUtils.SM4Encryptor(this.keyBytes)
									: SecurityUtils.SM4Decryptor(this.keyBytes);
							break;
						default:
							break;
					}
				} catch (CryptoException e) {
					LOGGER.error("Init_Crypto_Error");
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Stack_Message_Error", e);
					}
				}
			}
			return secureAdapter;
		}

		/**
		 * <h3 class="en-US">Getter method for Node initialize status</h3>
		 * <h3 class="zh-CN">节点初始化状态的Getter方法</h3>
		 *
		 * @return <span class="en-US">Node initialize status</span>
		 * <span class="zh-CN">节点初始化状态</span>
		 */
		public boolean isInitialized() {
			return initialized;
		}
	}

	/**
	 * <h2 class="en-US">Enumeration of Secure Algorithm</h2>
	 * <h2 class="zh-CN">安全算法的枚举类</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2012 12:37:28 $
	 */
	public enum SecureAlgorithm {
		RSA1024, RSA2048, SM2, AES128, AES192, AES256, DES, TRIPLE_DES, SM4
	}
}
