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
package org.nervousync.http.cert;

import org.nervousync.commons.Globals;
import org.nervousync.exceptions.http.CertInfoException;
import org.nervousync.utils.ConvertUtils;
import org.nervousync.utils.SecurityUtils;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Objects;

/**
 * <h2 class="en-US">Trust Certificate Library Define</h2>
 * <h2 class="zh-CN">允许的证书库定义</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $Date: Oct 30, 2018 15:38:36 $
 */
public final class TrustCert {
	/**
	 * <span class="en-US">Certificate library data bytes</span>
	 * <span class="zh-CN">证书库二进制字节数组</span>
	 */
	private byte[] certContent;
	/**
	 * <span class="en-US">Certificate password for read</span>
	 * <span class="zh-CN">读取证书的密码</span>
	 */
	private String certPassword;
	/**
	 * <span class="en-US">SHA256 value of certificate library data bytes</span>
	 * <span class="zh-CN">证书库二进制字节数组的SHA256值</span>
	 */
	private final String sha256;

	/**
	 * <h3 class="en-US">Private constructor method for TrustCert</h3>
	 * <h3 class="zh-CN">TrustCert私有构造方法</h3>
	 *
	 * @param certContent  <span class="en-US">Certificate library data bytes</span>
	 *                     <span class="zh-CN">证书库二进制字节数组</span>
	 * @param certPassword <span class="en-US">Certificate password for read</span>
	 *                     <span class="zh-CN">读取证书的密码</span>
	 */
	private TrustCert(byte[] certContent, String certPassword) {
		this.certContent = certContent;
		this.certPassword = certPassword;
		this.sha256 = ConvertUtils.toHex(SecurityUtils.SHA256(certContent));
	}

	/**
	 * <h3 class="en-US">Static method for generate TrustCert instance</h3>
	 * <h3 class="zh-CN">TrustCert私有构造方法</h3>
	 *
	 * @param certContent  <span class="en-US">Certificate library data bytes</span>
	 *                     <span class="zh-CN">证书库二进制字节数组</span>
	 * @param certPassword <span class="en-US">Certificate password for read</span>
	 *                     <span class="zh-CN">读取证书的密码</span>
	 * @return <span class="en-US">Generated TrustCert instance</span>
	 * <span class="zh-CN">生成的TrustCert实例对象</span>
	 */
	public static TrustCert newInstance(byte[] certContent, String certPassword) {
		return new TrustCert(certContent, certPassword);
	}

	/**
	 * <h3 class="en-US">Read certificate library and generate key manager array</h3>
	 * <h3 class="zh-CN">读取证书库中的证书并生成密钥管理器数组</h3>
	 *
	 * @return the key manager [ ]
	 * @throws CertInfoException the certificate exception
	 */
	public KeyManager[] generateKeyManagers() throws CertInfoException {
		try {
			KeyStore clientStore = KeyStore.getInstance("JKS");
			clientStore.load(new ByteArrayInputStream(this.certContent), this.certPassword.toCharArray());
			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
			keyManagerFactory.init(clientStore, this.certPassword.toCharArray());
			return keyManagerFactory.getKeyManagers();
		} catch (Exception e) {
			throw new CertInfoException(0x000000010001L, "Parse_Certificate_Error", e);
		}
	}

	/**
	 * <h3 class="en-US">Getter method for certificate library data bytes</h3>
	 * <h3 class="zh-CN">证书库二进制字节数组的Getter方法</h3>
	 *
	 * @return <span class="en-US">Certificate library data bytes</span>
	 * <span class="zh-CN">证书库二进制字节数组</span>
	 */
	public byte[] getCertContent() {
		return certContent;
	}

	/**
	 * <h3 class="en-US">Setter method for certificate library data bytes</h3>
	 * <h3 class="zh-CN">证书库二进制字节数组的Setter方法</h3>
	 *
	 * @param certContent <span class="en-US">Certificate library data bytes</span>
	 *                    <span class="zh-CN">证书库二进制字节数组</span>
	 */
	public void setCertContent(byte[] certContent) {
		this.certContent = certContent;
	}

	/**
	 * <h3 class="en-US">Getter method for certificate password</h3>
	 * <h3 class="zh-CN">证书读取密码的Getter方法</h3>
	 *
	 * @return <span class="en-US">Certificate password for read</span>
	 * <span class="zh-CN">读取证书的密码</span>
	 */
	public String getCertPassword() {
		return certPassword;
	}

	/**
	 * <h3 class="en-US">Setter method for certificate password</h3>
	 * <h3 class="zh-CN">证书读取密码的Setter方法</h3>
	 *
	 * @param certPassword <span class="en-US">Certificate password for read</span>
	 *                     <span class="zh-CN">读取证书的密码</span>
	 */
	public void setCertPassword(String certPassword) {
		this.certPassword = certPassword;
	}

	/**
	 * <h3 class="en-US">Getter method for SHA256 value</h3>
	 * <h3 class="zh-CN">SHA256验证值的Getter方法</h3>
	 * <p>
	 * return 	<span class="en-US">SHA256 value of certificate library data bytes</span>
	 * <span class="zh-CN">证书库二进制字节数组的SHA256值</span>
	 */
	public String getSha256() {
		return sha256;
	}

	/**
	 * (non-javadoc)
	 *
	 * @see Object#equals(Object)
	 */
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		TrustCert trustCert = (TrustCert) o;
		return Arrays.equals(certContent, trustCert.certContent)
				&& Objects.equals(certPassword, trustCert.certPassword);
	}

	/**
	 * (non-javadoc)
	 *
	 * @see Object#hashCode()
	 */
	@Override
	public int hashCode() {
		int result = Objects.hash(certPassword);
		result = Globals.MULTIPLIER * result + Arrays.hashCode(certContent);
		return result;
	}
}
