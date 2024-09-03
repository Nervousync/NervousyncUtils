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
package org.nervousync.http.security;

import org.nervousync.http.cert.TrustCert;
import org.nervousync.exceptions.http.CertInfoException;
import org.nervousync.utils.FileUtils;
import org.nervousync.utils.LoggerUtils;
import org.nervousync.utils.StringUtils;
import org.nervousync.utils.SystemUtils;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * <h2 class="en-US">X509 trust manager</h2>
 * <h2 class="zh-CN">X509证书管理器</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 18, 2020 20:51：28 $
 */
public class GeneX509TrustManager implements X509TrustManager {
	/**
	 * <span class="en-US">Multilingual supported logger instance</span>
	 * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	private final LoggerUtils.Logger logger = LoggerUtils.getLogger(this.getClass());
	/**
	 * <span class="en-US">Default password of read certificate from library</span>
	 * <span class="zh-CN">读取证书的默认密码</span>
	 */
	private static final String DEFAULT_PASSPHRASE = "changeit";
	/**
	 * <span class="en-US">Password of read certificate from library</span>
	 * <span class="zh-CN">读取证书的密码</span>
	 */
	private final String passPhrase;
	/**
	 * <span class="en-US">Trust certificate library list</span>
	 * <span class="zh-CN">信任证书库列表</span>
	 */
	private final List<TrustCert> trustCertList;
	/**
	 * <span class="en-US">Trust manager instance</span>
	 * <span class="zh-CN">信任管理器实例对象</span>
	 */
	private X509TrustManager trustManager = null;

	/**
	 * <h3 class="en-US">Private constructor method for GeneX509TrustManager</h3>
	 * <h3 class="zh-CN">GeneX509TrustManager私有构造方法</h3>
	 *
	 * @param passPhrase    <span class="en-US">Password of read certificate from library</span>
	 *                      <span class="zh-CN">读取证书的密码</span>
	 * @param trustCertList <span class="en-US">Trust certificate library list</span>
	 *                      <span class="zh-CN">信任证书库列表</span>
	 * @throws CertInfoException <span class="en-US">If not found X509TrustManager instance</span>
	 *                           <span class="zh-CN">当没有找到X509TrustManager实例对象时</span>
	 */
	private GeneX509TrustManager(String passPhrase, List<TrustCert> trustCertList) throws CertInfoException {
		this.passPhrase = StringUtils.notBlank(passPhrase) ? passPhrase : DEFAULT_PASSPHRASE;
		this.trustCertList = trustCertList;
		this.initManager();
	}

	/**
	 * <h3 class="en-US">Static method for generate GeneX509TrustManager instance</h3>
	 * <h3 class="zh-CN">静态方法用于生成GeneX509TrustManager实例对象</h3>
	 * Init gene x 509 trust manager.
	 *
	 * @param passPhrase    <span class="en-US">Password of read certificate from library</span>
	 *                      <span class="zh-CN">读取证书的密码</span>
	 * @param trustCertList <span class="en-US">Trust certificate library list</span>
	 *                      <span class="zh-CN">信任证书库列表</span>
	 * @return <span class="en-US">Generated GeneX509TrustManager instance</span>
	 * <span class="zh-CN">生成的GeneX509TrustManager实例对象</span>
	 * @throws CertInfoException <span class="en-US">If not found X509TrustManager instance</span>
	 *                           <span class="zh-CN">当没有找到X509TrustManager实例对象时</span>
	 */
	public static GeneX509TrustManager newInstance(final String passPhrase, final List<TrustCert> trustCertList)
			throws CertInfoException {
		return new GeneX509TrustManager(passPhrase, trustCertList);
	}

	/**
	 * <h3 class="en-US">Check client certificate is trusted</h3>
	 * <h3 class="zh-CN">检查客户端证书信任状态</h3>
	 *
	 * @param x509certificates <span class="en-US">the peer certificate chain</span>
	 *                         <span class="zh-CN">对等证书链</span>
	 * @param authType         <span class="en-US">the authentication type based on the client certificate</span>
	 *                         <span class="zh-CN">基于客户端证书的身份验证类型</span>
	 * @throws CertificateException <span class="en-US">If error occurs when check certificate</span>
	 *                              <span class="zh-CN">当检查证书时出现异常</span>
	 */
	@Override
	public void checkClientTrusted(final X509Certificate[] x509certificates, final String authType)
			throws CertificateException {
		this.trustManager.checkClientTrusted(x509certificates, authType);
	}

	/**
	 * <h3 class="en-US">Check server certificate is trusted</h3>
	 * <h3 class="zh-CN">检查客户端证书信任状态</h3>
	 *
	 * @param x509certificates <span class="en-US">the peer certificate chain</span>
	 *                         <span class="zh-CN">对等证书链</span>
	 * @param authType         <span class="en-US">the authentication type based on the client certificate</span>
	 *                         <span class="zh-CN">基于客户端证书的身份验证类型</span>
	 * @throws CertificateException <span class="en-US">If error occurs when check certificate</span>
	 *                              <span class="zh-CN">当检查证书时出现异常</span>
	 */
	@Override
	public void checkServerTrusted(X509Certificate[] x509certificates, String authType) throws CertificateException {
		this.trustManager.checkServerTrusted(x509certificates, authType);
	}

	/**
	 * <h3 class="en-US">Retrieve accepted issuers certificate array</h3>
	 * <h3 class="zh-CN">读取信任签发者的证书数组</h3>
	 *
	 * @return    <span class="en-US">Return an array of certificate authority certificates which are trusted for authenticating peers.</span>
	 * <span class="zh-CN">返回一组受信任的证书颁发机构证书，可用于对对等方进行身份验证。</span>
	 */
	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return this.trustManager.getAcceptedIssuers();
	}

	/**
	 * <h3 class="en-US">Initialize TrustManager instance</h3>
	 * <h3 class="zh-CN">初始化证书信任管理器实例对象</h3>
	 *
	 * @throws CertInfoException <span class="en-US">If not found X509TrustManager instance</span>
	 *                           <span class="zh-CN">当没有找到X509TrustManager实例对象时</span>
	 */
	private void initManager() throws CertInfoException {
		try {
			KeyStore keyStore = KeyStore.getInstance("JKS");
			if (!FileUtils.isExists(SystemUtils.systemCertPath())) {
				this.logger.warn("System_Certificate_Not_Found_Warn");
			} else {
				keyStore.load(FileUtils.loadFile(SystemUtils.systemCertPath()), this.passPhrase.toCharArray());
			}
			for (TrustCert trustCert : this.trustCertList) {
				keyStore.load(new ByteArrayInputStream(trustCert.getCertContent()),
						trustCert.getCertPassword().toCharArray());
			}
			TrustManagerFactory trustManagerFactory =
					TrustManagerFactory.getInstance("SunX509", "SunJSSE");
			trustManagerFactory.init(keyStore);
			for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
				if (trustManager instanceof X509TrustManager) {
					this.trustManager = (X509TrustManager) trustManager;
					return;
				}
			}
		} catch (Exception e) {
			throw new CertInfoException(0x000000160001L, "Init_Trust_Manager_Certificate_Error", e);
		}

		throw new CertInfoException(0x000000160002L, "NotFound_X509TrustManager_Certificate_Error");
	}
}
