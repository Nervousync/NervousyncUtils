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
package org.nervousync.utils;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.nervousync.commons.Globals;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/**
 * <h2 class="en-US">Certificate Utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Generate Keypair</ul>
 *     <ul>Signature and generate X.509 certificate</ul>
 *     <ul>Parse X.509 certificate from certificate file, PKCS12 file or binary data arrays</ul>
 *     <ul>Validate X.509 certificate period and signature</ul>
 *     <ul>Read PublicKey/PrivateKey from binary data arrays or PKCS12 file</ul>
 *     <ul>Signature and generate PKCS12 file</ul>
 * </span>
 * <h2 class="zh-CN">数字证书工具集</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>生成密钥对</ul>
 *     <ul>签发X.509证书</ul>
 *     <ul>从证书文件、PKCS12文件或二进制数据中读取X.509证书</ul>
 *     <ul>验证X.509证书的有效期、数字签名</ul>
 *     <ul>从PKCS12文件或二进制数据中读取公钥和私钥</ul>
 *     <ul>生成PKCS12文件</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Jun 25, 2015 16:26:15 $
 */
public final class CertificateUtils {
	/**
	 * <span class="en-US">Multilingual supported logger instance</span>
	 * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(CertificateUtils.class);

	static {
		/* Add Bouncy Castle Provider */
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * <h3 class="en-US">Private constructor for CertificateUtils</h3>
	 * <h3 class="zh-CN">数字证书工具集的私有构造函数</h3>
	 */
	private CertificateUtils() {
	}

	/**
	 * <h3 class="en-US">Generate KeyPair using given algorithm/secure random algorithm/key size</h3>
	 * <h3 class="zh-CN">根据给定的算法、安全随机数算法、密钥长度生成密钥对</h3>
	 *
	 * @param algorithm       <span class="en-US">Algorithm</span>
	 *                        <span class="zh-CN">算法</span>
	 * @param randomAlgorithm <span class="en-US">Secure Random Algorithm</span>
	 *                        <span class="zh-CN">安全随机数算法</span>
	 * @param stdName         <span class="en-US">The standard name of the to-be-generated EC domain parameters</span>
	 *                        <span class="zh-CN">待生成EC域参数的标准名称</span>
	 * @param keySize         <span class="en-US">Key size</span>
	 *                        <span class="zh-CN">密钥长度</span>
	 * @return <span class="en-US">Generated key pair</span>
	 * <span class="zh-CN">生成的密钥对</span>
	 */
	public static KeyPair keyPair(final String algorithm, final String randomAlgorithm,
	                              final String stdName, final int keySize) {
		if (keySize % 128 != 0) {
			LOGGER.error("Key_Size_Invalid_Error");
			return null;
		}

		KeyPair keyPair = null;
		try {
			SecureRandom secureRandom;
			if (StringUtils.isEmpty(randomAlgorithm)) {
				LOGGER.warn("Random_Algorithm_Default_Warn");
				secureRandom = SecureRandom.getInstance("SHA1PRNG");
			} else {
				secureRandom = SecureRandom.getInstance(randomAlgorithm);
			}

			//	Initialize keyPair instance
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, "BC");
			if (algorithm.equalsIgnoreCase("EC")) {
				ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(stdName);
				keyPairGenerator.initialize(ecGenParameterSpec, secureRandom);
			} else {
				keyPairGenerator.initialize(keySize, secureRandom);
			}
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
			LOGGER.error("Init_Key_Pair_Generator_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}
		return keyPair;
	}

	/**
	 * <h3 class="en-US">Convert public key to X.509 certificate, signature certificate by given private key and signature algorithm</h3>
	 * <h3 class="zh-CN">转换PublicKey为X509证书，并使用给定的私钥和签名算法进行签名</h3>
	 *
	 * @param publicKey     <span class="en-US">Public key</span>
	 *                      <span class="zh-CN">公钥</span>
	 * @param serialNumber  <span class="en-US">Certificate Serial Number</span>
	 *                      <span class="zh-CN">证书的序列号</span>
	 * @param beginDate     <span class="en-US">Certificate Begin Date</span>
	 *                      <span class="zh-CN">证书有效期起始时间</span>
	 * @param endDate       <span class="en-US">Certificate End Date</span>
	 *                      <span class="zh-CN">证书有效期截至时间</span>
	 * @param commonName    <span class="en-US">Certificate Common Name</span>
	 *                      <span class="zh-CN">证书的公用名称（CN字段）</span>
	 * @param signKey       <span class="en-US">Certificate Signer Private Key</span>
	 *                      <span class="zh-CN">证书签发者的私钥</span>
	 * @param signAlgorithm <span class="en-US">Signature Algorithm</span>
	 *                      <span class="zh-CN">签名算法</span>
	 * @return <span class="en-US">Generated X.509 certificate</span>
	 * <span class="zh-CN">生成的X.509格式证书</span>
	 */
	public static X509Certificate x509(final PublicKey publicKey, final long serialNumber,
	                                   final Date beginDate, final Date endDate, final String commonName,
	                                   final PrivateKey signKey, final String signAlgorithm) {
		if (publicKey == null || signKey == null || StringUtils.isEmpty(signAlgorithm)) {
			return null;
		}
		X500Name subjectDN = new X500Name("CN=" + commonName);
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		X509v3CertificateBuilder x509v3CertificateBuilder =
				new X509v3CertificateBuilder(subjectDN, BigInteger.valueOf(serialNumber),
						beginDate, endDate, subjectDN, publicKeyInfo);
		try {
			x509v3CertificateBuilder.addExtension(Extension.basicConstraints,
					Boolean.FALSE, new BasicConstraints(Boolean.FALSE));
			ContentSigner contentSigner = new JcaContentSignerBuilder(signAlgorithm).setProvider("BC").build(signKey);
			X509CertificateHolder certificateHolder = x509v3CertificateBuilder.build(contentSigner);
			return new JcaX509CertificateConverter().getCertificate(certificateHolder);
		} catch (OperatorCreationException | GeneralSecurityException | IOException e) {
			LOGGER.error("PKCS12_Generate_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Read X.509 Certificate</h3>
	 * <h3 class="zh-CN">读取X.509格式的证书</h3>
	 *
	 * @param certBytes <span class="en-US">Certificate Data Bytes</span>
	 *                  <span class="zh-CN">证书的字节数组</span>
	 * @return <span class="en-US">Read X.509 certificate or null for invalid</span>
	 * <span class="zh-CN">读取的X.509证书， 如果数据非法，则返回null</span>
	 */
	public static X509Certificate x509(final byte[] certBytes) {
		return x509(certBytes, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Read X.509 Certificate and verified by given public key</h3>
	 * <h3 class="zh-CN">读取X.509格式的证书并使用给定的公钥验证证书签名</h3>
	 *
	 * @param certBytes <span class="en-US">Certificate Data Bytes</span>
	 *                  <span class="zh-CN">证书的字节数组</span>
	 * @param verifyKey <span class="en-US">Verifier Public Key</span>
	 *                  <span class="zh-CN">验证签名使用的公钥</span>
	 * @return <span class="en-US">Read X.509 certificate or null for invalid</span>
	 * <span class="zh-CN">读取的X.509证书， 如果数据非法或证书签名验证失败，则返回null</span>
	 */
	public static X509Certificate x509(final byte[] certBytes, final PublicKey verifyKey) {
		return x509(certBytes, verifyKey, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Read X.509 Certificate and check certificate validity period</h3>
	 * <h3 class="zh-CN">读取X.509格式的证书并检查证书是否在有效期内</h3>
	 *
	 * @param certBytes     <span class="en-US">Certificate Data Bytes</span>
	 *                      <span class="zh-CN">证书的字节数组</span>
	 * @param checkValidity <span class="en-US"><code>true</code> for check certificate signature, <code>false</code> for not check</span>
	 *                      <span class="zh-CN"><code>true</code>检查证书有效期, <code>false</code>不检查证书有效期</span>
	 * @return <span class="en-US">Read X.509 certificate or null for invalid</span>
	 * <span class="zh-CN">读取的X.509证书， 如果数据非法或证书未在有效期内，则返回null</span>
	 */
	public static X509Certificate x509(final byte[] certBytes, final boolean checkValidity) {
		return x509(certBytes, null, checkValidity);
	}

	/**
	 * <h3 class="en-US">Read X.509 Certificate, verified by given public key and check certificate validity period</h3>
	 * <h3 class="zh-CN">读取X.509格式的证书，使用给定的公钥验证证书签名并检查证书是否在有效期内</h3>
	 *
	 * @param certBytes     <span class="en-US">Certificate Data Bytes</span>
	 *                      <span class="zh-CN">证书的字节数组</span>
	 * @param verifyKey     <span class="en-US">Verifier Public Key</span>
	 *                      <span class="zh-CN">验证签名使用的公钥</span>
	 * @param checkValidity <span class="en-US"><code>true</code> for check certificate signature, <code>false</code> for not check</span>
	 *                      <span class="zh-CN"><code>true</code>检查证书有效期, <code>false</code>不检查证书有效期</span>
	 * @return <span class="en-US">Read X.509 certificate or null for invalid</span>
	 * <span class="zh-CN">读取的X.509证书， 如果数据非法、证书签名验证失败或证书未在有效期内，则返回null</span>
	 */
	public static X509Certificate x509(final byte[] certBytes, final PublicKey verifyKey, final boolean checkValidity) {
		X509Certificate x509Certificate;
		try {
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
			ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(certBytes);
			x509Certificate = (X509Certificate) certificateFactory.generateCertificate(byteArrayInputStream);
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Certificate_SN_Debug", x509Certificate.getSerialNumber().toString());
			}
			if (checkValidity) {
				x509Certificate.checkValidity();
			}
			if (verifyKey != null) {
				x509Certificate.verify(verifyKey, "BC");
			}
		} catch (Exception e) {
			LOGGER.error("Certificate_Invalid_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			x509Certificate = null;
		}
		return x509Certificate;
	}

	/**
	 * <h3 class="en-US">Check X.509 Certificate Validity Period</h3>
	 * <h3 class="zh-CN">检查证书是否在有效期内</h3>
	 *
	 * @param x509Certificate <span class="en-US">X.509 Certificate</span>
	 *                        <span class="zh-CN">X.509证书</span>
	 * @return <span class="en-US">Verify Result. <code>true</code> for success, <code>false</code> for failed</span>
	 * <span class="zh-CN">验证结果。<code>true</code>验证通过, <code>false</code>验证失败</span>
	 */
	public static boolean verify(final X509Certificate x509Certificate) {
		return verify(x509Certificate, null, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Verify X.509 Certificate Signature by given Public Key</h3>
	 * <h3 class="zh-CN">使用给定的公钥检查证书签名是否有效</h3>
	 *
	 * @param x509Certificate <span class="en-US">X.509 Certificate</span>
	 *                        <span class="zh-CN">X.509证书</span>
	 * @param verifyKey       <span class="en-US">Verifier Public Key</span>
	 *                        <span class="zh-CN">验证签名使用的公钥</span>
	 * @return <span class="en-US">Verify Result. <code>true</code> for success, <code>false</code> for failed</span>
	 * <span class="zh-CN">验证结果。<code>true</code>验证通过, <code>false</code>验证失败</span>
	 */
	public static boolean verify(final X509Certificate x509Certificate, final PublicKey verifyKey) {
		return verify(x509Certificate, verifyKey, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Check X.509 Certificate Validity Period and Verify Signature by given Public Key</h3>
	 * <h3 class="zh-CN">检查证书是否在有效期内并使用给定的公钥检查证书签名是否有效</h3>
	 *
	 * @param x509Certificate <span class="en-US">X.509 Certificate</span>
	 *                        <span class="zh-CN">X.509证书</span>
	 * @param verifyKey       <span class="en-US">Verifier Public Key</span>
	 *                        <span class="zh-CN">验证签名使用的公钥</span>
	 * @param checkValidity   <span class="en-US"><code>true</code> for check certificate signature, <code>false</code> for not check</span>
	 *                        <span class="zh-CN"><code>true</code>检查证书有效期, <code>false</code>不检查证书有效期</span>
	 * @return <span class="en-US">Verify Result. <code>true</code> for success, <code>false</code> for failed</span>
	 * <span class="zh-CN">验证结果。<code>true</code>验证通过, <code>false</code>验证失败</span>
	 */
	public static boolean verify(final X509Certificate x509Certificate, final PublicKey verifyKey,
	                             final boolean checkValidity) {
		if (x509Certificate == null) {
			return Boolean.FALSE;
		}
		try {
			if (checkValidity) {
				x509Certificate.checkValidity();
			}
			x509Certificate.verify((verifyKey == null) ? x509Certificate.getPublicKey() : verifyKey, "BC");
			return Boolean.TRUE;
		} catch (Exception e) {
			LOGGER.error("Certificate_Invalid_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Read X.509 certificate from Keystore/PKCS12 data bytes</h3>
	 * <h3 class="zh-CN">从Keystore/PKCS12的二进制数据中读取X.509证书</h3>
	 *
	 * @param storeBytes <span class="en-US">Keystore/PKCS12 data bytes</span>
	 *                   <span class="zh-CN">Keystore/PKCS12的二进制数据</span>
	 * @param certAlias  <span class="en-US">Certificate alias name</span>
	 *                   <span class="zh-CN">证书别名</span>
	 * @param password   <span class="en-US">Password of Keystore/PKCS12</span>
	 *                   <span class="zh-CN">Keystore/PKCS12的密码</span>
	 * @return <span class="en-US">Read X.509 certificate or null for invalid</span>
	 * <span class="zh-CN">读取的X.509证书， 如果数据非法或未找到别名指定的证书，则返回null</span>
	 */
	public static X509Certificate x509(final byte[] storeBytes, final String certAlias, final String password) {
		return x509(storeBytes, certAlias, password, null, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Read X.509 certificate from file. File format: Keystore/PKCS12</h3>
	 * <h3 class="zh-CN">从指定路径的Keystore/PKCS12文件中读取X.509证书， 文件格式为：Keystore/PKCS12</h3>
	 *
	 * @param storePath <span class="en-US">Keystore/PKCS12 file path</span>
	 *                  <span class="zh-CN">Keystore/PKCS12文件路径</span>
	 * @param certAlias <span class="en-US">Certificate alias name</span>
	 *                  <span class="zh-CN">证书别名</span>
	 * @param password  <span class="en-US">Password of Keystore/PKCS12</span>
	 *                  <span class="zh-CN">Keystore/PKCS12的密码</span>
	 * @return <span class="en-US">Read X.509 certificate or null for invalid</span>
	 * <span class="zh-CN">读取的X.509证书， 如果数据非法或未找到别名指定的证书，则返回null</span>
	 */
	public static X509Certificate x509(final String storePath, final String certAlias, final String password) {
		try {
			return x509(FileUtils.readFileBytes(storePath), certAlias, password);
		} catch (IOException e) {
			return null;
		}
	}

	/**
	 * <h3 class="en-US">Read X.509 certificate from Keystore/PKCS12 data bytes, Validity Period and Verify Signature by given Public Key.</h3>
	 * <h3 class="zh-CN">从Keystore/PKCS12的二进制数据中读取X.509证书，检查证书是否在有效期内并使用给定的公钥检查证书签名是否有效</h3>
	 *
	 * @param storeBytes    <span class="en-US">Keystore/PKCS12 data bytes</span>
	 *                      <span class="zh-CN">Keystore/PKCS12的二进制数据</span>
	 * @param certAlias     <span class="en-US">Certificate alias name</span>
	 *                      <span class="zh-CN">证书别名</span>
	 * @param password      <span class="en-US">Password of Keystore/PKCS12</span>
	 *                      <span class="zh-CN">Keystore/PKCS12的密码</span>
	 * @param verifyKey     <span class="en-US">Verifier Public Key</span>
	 *                      <span class="zh-CN">验证签名使用的公钥</span>
	 * @param checkValidity <span class="en-US"><code>true</code> for check certificate signature, <code>false</code> for not check</span>
	 *                      <span class="zh-CN"><code>true</code>检查证书有效期, <code>false</code>不检查证书有效期</span>
	 * @return <span class="en-US">Read X.509 certificate or null for invalid</span>
	 * <span class="zh-CN">读取的X.509证书， 如果数据非法、未找到别名指定的证书、证书未在有效期或证书签名错误，则返回null</span>
	 */
	public static X509Certificate x509(final byte[] storeBytes, final String certAlias, final String password,
	                                   final PublicKey verifyKey, final boolean checkValidity) {
		return Optional.ofNullable(loadKeyStore(storeBytes, password))
				.filter(keyStore -> checkKey(keyStore, certAlias))
				.map(keyStore -> {
					X509Certificate x509Certificate;
					try {
						x509Certificate = (X509Certificate) keyStore.getCertificate(certAlias);
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Certificate_SN_Debug", x509Certificate.getSerialNumber().toString());
						}
						if (checkValidity) {
							x509Certificate.checkValidity();
						}
						if (verifyKey != null) {
							x509Certificate.verify(verifyKey, "BC");
						}
					} catch (Exception e) {
						LOGGER.error("Certificate_Invalid_Error");
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Stack_Message_Error", e);
						}
						x509Certificate = null;
					}
					return x509Certificate;
				})
				.orElse(null);
	}

	/**
	 * <h3 class="en-US">Verify x509 certificate contains given domain name</h3>
	 * <h3 class="zh-CN">验证x509证书中包含给定的域名</h3>
	 *
	 * @param x509Certificate <span class="en-US">x509 certificate</span>
	 *                        <span class="zh-CN">x509证书</span>
	 * @param domainName      <span class="en-US">Will check for Domain name</span>
	 *                        <span class="zh-CN">将要检查的域名</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean matchDomain(final X509Certificate x509Certificate, final String domainName) {
		if (x509Certificate == null || StringUtils.isEmpty(domainName)) {
			return Boolean.FALSE;
		}
		try {
			x509Certificate.checkValidity();
			if (x509Certificate.getVersion() == 3) {
				Collection<List<?>> collection = x509Certificate.getSubjectAlternativeNames();
				if (collection != null) {
					boolean matchResult;
					if (IPUtils.isIPv4Address(domainName) || IPUtils.isIPv6Address(domainName)) {
						matchResult = collection.stream()
								//  See RFC 5280 section 4.2.1.6
								.filter(dataList -> ((Integer) dataList.get(0)) == 7)
								.map(dataList -> (String) dataList.get(1))
								.anyMatch(domainName::equalsIgnoreCase);
					} else {
						matchResult = collection.stream()
								//  See RFC 5280 section 4.2.1.6
								.filter(dataList -> ((Integer) dataList.get(0)) == 2)
								.map(dataList -> (String) dataList.get(1))
								.anyMatch(matchDomain -> matchDomain(matchDomain, domainName));
					}
					if (matchResult) {
						return Boolean.TRUE;
					}
				}
			}
			LdapName ldapName = new LdapName(x509Certificate.getSubjectX500Principal().getName());
			String matchDomain = ldapName.getRdns().stream()
					.filter(rdn -> rdn.getType().equalsIgnoreCase("CN"))
					.findFirst()
					.map(rdn -> (String) rdn.getValue())
					.orElse(Globals.DEFAULT_VALUE_STRING);
			return matchDomain(matchDomain, domainName);
		} catch (CertificateNotYetValidException | CertificateExpiredException | InvalidNameException |
		         CertificateParsingException e) {
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Read the x509 certificate from the given pem file location and match domain name if exists</h3>
	 * <h3 class="zh-CN">根据给定的pem文件位置读取x509证书，如果给定域名信息则匹配证书中的域名信息</h3>
	 *
	 * @param pemPath    <span class="en-US">pem file path</span>
	 *                   <span class="zh-CN">pem文件路径</span>
	 * @param domainName <span class="en-US">Will check for Domain name</span>
	 *                   <span class="zh-CN">将要检查的域名</span>
	 * @return <span class="en-US">Read x509 certificate instance or null if file not found or data bytes invalid</span>
	 * <span class="zh-CN">读取的x509证书，如果文件不存在或二进制数据非法则返回null</span>
	 */
	public static X509Certificate x509(final String pemPath, final String domainName) {
		if (StringUtils.isEmpty(pemPath) || !FileUtils.isExists(pemPath)) {
			return null;
		}

		try (FileReader fileReader = new FileReader(pemPath)) {
			PEMParser pemParser = new PEMParser(fileReader);
			PemObject readObject;
			while ((readObject = pemParser.readPemObject()) != null) {
				X509Certificate x509Certificate = x509(readObject.getContent());
				if (x509Certificate != null && matchDomain(x509Certificate, domainName)) {
					return x509Certificate;
				}
			}
			return null;
		} catch (IOException e) {
			LOGGER.error("Data_Read_Key_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return null;
		}
	}

	/**
	 * <h3 class="en-US">Generate PublicKey from key data bytes and given algorithm</h3>
	 * <h3 class="zh-CN">根据给定的算法和二进制数据生成公钥</h3>
	 *
	 * @param algorithm <span class="en-US">Key algorithm</span>
	 *                  <span class="zh-CN">算法</span>
	 * @param keyBytes  <span class="en-US">Key data bytes</span>
	 *                  <span class="zh-CN">二进制数据</span>
	 * @return <span class="en-US">Generated publicKey or null if data bytes invalid</span>
	 * <span class="zh-CN">生成的公钥，如果二进制数据非法则返回null</span>
	 */
	public static PublicKey publicKey(final String algorithm, final byte[] keyBytes) {
		try {
			return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(keyBytes));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			LOGGER.error("Data_Generate_Key_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Read PrivateKey from pem file and given algorithm</h3>
	 * <h3 class="zh-CN">根据给定的算法和pem文件路径读取私钥</h3>
	 *
	 * @param pemPath <span class="en-US">pem file path</span>
	 *                <span class="zh-CN">pem文件路径</span>
	 * @return <span class="en-US">Read privateKey instance or null if file not found or data bytes invalid</span>
	 * <span class="zh-CN">读取的私钥，如果文件不存在或二进制数据非法则返回null</span>
	 */
	public static PrivateKey privateKey(final String pemPath) {
		if (StringUtils.isEmpty(pemPath) || !FileUtils.isExists(pemPath)) {
			return null;
		}

		try (FileReader fileReader = new FileReader(pemPath)) {
			PEMParser pemParser = new PEMParser(fileReader);
			JcaPEMKeyConverter jcaPEMKeyConverter = new JcaPEMKeyConverter();
			return jcaPEMKeyConverter.getPrivateKey(PrivateKeyInfo.getInstance(pemParser.readObject()));
		} catch (IOException e) {
			LOGGER.error("Data_Read_Key_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return null;
		}
	}

	/**
	 * <h3 class="en-US">Generate PrivateKey from key data bytes and given algorithm</h3>
	 * <h3 class="zh-CN">根据给定的算法和二进制数据生成私钥</h3>
	 *
	 * @param algorithm <span class="en-US">Key algorithm</span>
	 *                  <span class="zh-CN">算法</span>
	 * @param keyBytes  <span class="en-US">Key data bytes</span>
	 *                  <span class="zh-CN">二进制数据</span>
	 * @return <span class="en-US">Generated privateKey or null if data bytes invalid</span>
	 * <span class="zh-CN">生成的私钥，如果二进制数据非法则返回null</span>
	 */
	public static PrivateKey privateKey(final String algorithm, final byte[] keyBytes) {
		try {
			return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			LOGGER.error("Data_Generate_Key_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return null;
		}
	}

	/**
	 * <h3 class="en-US">Read PrivateKey from Keystore/PKCS12 data bytes</h3>
	 *
	 * @param storeBytes <span class="en-US">Keystore/PKCS12 data bytes</span>
	 *                   <span class="zh-CN">Keystore/PKCS12的二进制数据</span>
	 * @param certAlias  <span class="en-US">Certificate alias name</span>
	 *                   <span class="zh-CN">证书别名</span>
	 * @param password   <span class="en-US">Password of Keystore/PKCS12</span>
	 *                   <span class="zh-CN">Keystore/PKCS12的密码</span>
	 * @return <span class="en-US">Read PrivateKey or null if data bytes invalid</span>
	 * <span class="zh-CN">读取的私钥， 如果数据非法、未找到别名指定的证书，则返回null</span>
	 */
	public static PrivateKey privateKey(final byte[] storeBytes, final String certAlias, final String password) {
		KeyStore keyStore = loadKeyStore(storeBytes, password);
		if (keyStore != null && CertificateUtils.checkKey(keyStore, certAlias)) {
			return CertificateUtils.privateKey(keyStore, certAlias, password);
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Read PrivateKey from file. File format: Keystore/PKCS12</h3>
	 * <h3 class="zh-CN">从指定路径的Keystore/PKCS12文件中读取私钥， 文件格式为：Keystore/PKCS12</h3>
	 *
	 * @param storePath <span class="en-US">Keystore/PKCS12 file path</span>
	 *                  <span class="zh-CN">Keystore/PKCS12文件路径</span>
	 * @param certAlias <span class="en-US">Certificate alias name</span>
	 *                  <span class="zh-CN">证书别名</span>
	 * @param password  <span class="en-US">Password of Keystore/PKCS12</span>
	 *                  <span class="zh-CN">Keystore/PKCS12的密码</span>
	 * @return <span class="en-US">Read PrivateKey or null if invalid</span>
	 * <span class="zh-CN">读取的私钥， 如果数据非法或未找到别名指定的证书，则返回null</span>
	 */
	public static PrivateKey privateKey(final String storePath, final String certAlias, final String password) {
		KeyStore keyStore = loadKeyStore(storePath, password);
		if (keyStore != null && CertificateUtils.checkKey(keyStore, certAlias)) {
			return CertificateUtils.privateKey(keyStore, certAlias, password);
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Generate PKCS12 Data Bytes, include PrivateKey, PublicKey and generate signature</h3>
	 * <h3 class="zh-CN">生成PKCS12格式的证书二进制数据，包含公钥、私钥及数字签名</h3>
	 *
	 * @param keyPair       <span class="en-US">Key pair</span>
	 *                      <span class="zh-CN">密钥对</span>
	 * @param serialNumber  <span class="en-US">Certificate Serial Number</span>
	 *                      <span class="zh-CN">证书的序列号</span>
	 * @param beginDate     <span class="en-US">Certificate Begin Date</span>
	 *                      <span class="zh-CN">证书有效期起始时间</span>
	 * @param endDate       <span class="en-US">Certificate End Date</span>
	 *                      <span class="zh-CN">证书有效期截至时间</span>
	 * @param certAlias     <span class="en-US">Certificate alias name</span>
	 *                      <span class="zh-CN">证书别名</span>
	 * @param commonName    <span class="en-US">Certificate Common Name</span>
	 *                      <span class="zh-CN">证书的公用名称（CN字段）</span>
	 * @param passWord      <span class="en-US">Password of Keystore/PKCS12</span>
	 *                      <span class="zh-CN">Keystore/PKCS12的密码</span>
	 * @param signKey       <span class="en-US">Certificate Signer Private Key</span>
	 *                      <span class="zh-CN">证书签发者的私钥</span>
	 * @param signAlgorithm <span class="en-US">Signature Algorithm</span>
	 *                      <span class="zh-CN">签名算法</span>
	 * @return <span class="en-US">Generated PKCS12 data bytes or 0 length byte array if has error</span>
	 * <span class="zh-CN">生成的PKCS12格式二进制数据，如果出错则返回长度为0的二进制数据</span>
	 */
	public static byte[] PKCS12(final KeyPair keyPair, final long serialNumber,
	                            final Date beginDate, final Date endDate, final String certAlias,
	                            final String commonName, final String passWord,
	                            final PrivateKey signKey, final String signAlgorithm) {
		char[] charArray;
		if (StringUtils.isEmpty(passWord)) {
			charArray = Globals.DEFAULT_VALUE_STRING.toCharArray();
		} else {
			charArray = passWord.toCharArray();
		}
		X500Name subjectDN = new X500Name("CN=" + commonName);
		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
		X509v3CertificateBuilder x509v3CertificateBuilder =
				new X509v3CertificateBuilder(subjectDN, BigInteger.valueOf(serialNumber),
						beginDate, endDate, subjectDN, publicKeyInfo);
		ByteArrayOutputStream byteArrayOutputStream = null;
		try {
			x509v3CertificateBuilder.addExtension(Extension.basicConstraints, Boolean.FALSE,
					new BasicConstraints(Boolean.FALSE));
			ContentSigner contentSigner =
					new JcaContentSignerBuilder(signAlgorithm).setProvider("BC")
							.build(signKey == null ? keyPair.getPrivate() : signKey);
			X509CertificateHolder certificateHolder = x509v3CertificateBuilder.build(contentSigner);
			X509Certificate x509Certificate =
					new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);

			KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
			keyStore.load(null, null);
			keyStore.setKeyEntry(certAlias, keyPair.getPrivate(), charArray, new Certificate[]{x509Certificate});
			byteArrayOutputStream = new ByteArrayOutputStream();
			keyStore.store(byteArrayOutputStream, charArray);
			return byteArrayOutputStream.toByteArray();
		} catch (OperatorCreationException | GeneralSecurityException | IOException e) {
			LOGGER.error("PKCS12_Generate_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return new byte[0];
		} finally {
			IOUtils.closeStream(byteArrayOutputStream);
		}
	}

	/**
	 * <h3 class="en-US">Read PKCS12 KeyStore from data bytes</h3>
	 * <h3 class="zh-CN">从二进制数据中读取PKCS12格式的密钥库</h3>
	 *
	 * @param storeBytes <span class="en-US">Keystore/PKCS12 data bytes</span>
	 *                   <span class="zh-CN">Keystore/PKCS12的二进制数据</span>
	 * @param password   <span class="en-US">Password of Keystore/PKCS12</span>
	 *                   <span class="zh-CN">Keystore/PKCS12的密码</span>
	 * @return <span class="en-US">Read PKCS12 KeyStore or null for error</span>
	 * <span class="zh-CN">读取的PKCS12格式密钥库， 如果数据非法则返回null</span>
	 */
	public static KeyStore loadKeyStore(final byte[] storeBytes, final String password) {
		return loadKeyStore(new ByteArrayInputStream(storeBytes), password);
	}

	/**
	 * <h3 class="en-US">Read PKCS12 KeyStore from given file path</h3>
	 * <h3 class="zh-CN">从指定的文件位置读取PKCS12格式的密钥库</h3>
	 *
	 * @param storePath <span class="en-US">Keystore/PKCS12 file path</span>
	 *                  <span class="zh-CN">Keystore/PKCS12文件路径</span>
	 * @param password  <span class="en-US">Password of Keystore/PKCS12</span>
	 *                  <span class="zh-CN">Keystore/PKCS12的密码</span>
	 * @return <span class="en-US">Read PKCS12 KeyStore or null for error</span>
	 * <span class="zh-CN">读取的PKCS12格式密钥库， 如果文件未找到或数据非法则返回null</span>
	 */
	public static KeyStore loadKeyStore(final String storePath, final String password) {
		try {
			return loadKeyStore(new FileInputStream(storePath), password);
		} catch (FileNotFoundException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Load_Key_Store_Error", e);
			}
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Read PKCS12 KeyStore from input stream</h3>
	 * <h3 class="zh-CN">从输入流读取PKCS12格式的密钥库</h3>
	 *
	 * @param inputStream <span class="en-US">Input stream</span>
	 *                    <span class="zh-CN">输入流</span>
	 * @param password    <span class="en-US">Password of Keystore/PKCS12</span>
	 *                    <span class="zh-CN">Keystore/PKCS12的密码</span>
	 * @return <span class="en-US">Read PKCS12 KeyStore or null for error</span>
	 * <span class="zh-CN">读取的PKCS12格式密钥库， 如果数据非法则返回null</span>
	 */
	public static KeyStore loadKeyStore(final InputStream inputStream, final String password) {
		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance("PKCS12", "BC");
			keyStore.load(inputStream, password == null ? null : password.toCharArray());
		} catch (Exception e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Load_Key_Store_Error", e);
			}
			keyStore = null;
		} finally {
			IOUtils.closeStream(inputStream);
		}
		return keyStore;
	}

	/**
	 * <h3 class="en-US">Check PKCS12 contains certificate alias</h3>
	 * <h3 class="zh-CN">检查PKCS12标准的密钥库中是否包含给定别名的证书</h3>
	 *
	 * @param keyStore  <span class="en-US">PKCS12 KeyStore</span>
	 *                  <span class="zh-CN">PKCS12标准的密钥库</span>
	 * @param certAlias <span class="en-US">Certificate alias name</span>
	 *                  <span class="zh-CN">证书别名</span>
	 * @return <span class="en-US">Check result. <code>true</code> for exists <code>false</code> for not found</span>
	 * <span class="zh-CN">检查结果 <code>true</code>证书存在 <code>false</code>证书不存在</span>
	 */
	public static boolean checkKey(final KeyStore keyStore, final String certAlias) {
		if (keyStore == null || certAlias == null) {
			return Boolean.FALSE;
		}
		try {
			return keyStore.isKeyEntry(certAlias);
		} catch (KeyStoreException e) {
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Read X.509 certificate from PKCS12 KeyStore</h3>
	 * <h3 class="zh-CN">从PKCS12格式的密钥库中读取X.509证书</h3>
	 *
	 * @param keyStore  <span class="en-US">PKCS12 KeyStore</span>
	 *                  <span class="zh-CN">PKCS12标准的密钥库</span>
	 * @param certAlias <span class="en-US">Certificate alias name</span>
	 *                  <span class="zh-CN">证书别名</span>
	 * @return <span class="en-US">Read X.509 certificate or null for not found</span>
	 * <span class="zh-CN">读取的X.509证书， 如果数据非法、未找到别名指定的证书，则返回null</span>
	 */
	public static X509Certificate x509(final KeyStore keyStore, final String certAlias) {
		try {
			return (X509Certificate) keyStore.getCertificate(certAlias);
		} catch (KeyStoreException e) {
			LOGGER.error("Read_Certificate_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return null;
		}
	}

	/**
	 * <h3 class="en-US">Read PrivateKey from PKCS12 KeyStore</h3>
	 * <h3 class="zh-CN">从PKCS12格式的密钥库中读取私钥</h3>
	 *
	 * @param keyStore  <span class="en-US">PKCS12 KeyStore</span>
	 *                  <span class="zh-CN">PKCS12标准的密钥库</span>
	 * @param certAlias <span class="en-US">Certificate alias name</span>
	 *                  <span class="zh-CN">证书别名</span>
	 * @param password  <span class="en-US">Password of Keystore/PKCS12</span>
	 *                  <span class="zh-CN">Keystore/PKCS12的密码</span>
	 * @return <span class="en-US">Read PrivateKey or null if invalid</span>
	 * <span class="zh-CN">读取的私钥， 如果数据非法或未找到别名指定的证书，则返回null</span>
	 */
	public static PrivateKey privateKey(final KeyStore keyStore, final String certAlias, final String password) {
		try {
			return (PrivateKey) keyStore.getKey(certAlias, password == null ? null : password.toCharArray());
		} catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
			LOGGER.error("Read_Private_Key_From_Store_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return null;
		}
	}

	/**
	 * <h3 class="en-US">Match domain name</h3>
	 * <h3 class="zh-CN">验证泛域名</h3>
	 *
	 * @param matchDomain <span class="en-US">generic domain name</span>
	 *                    <span class="zh-CN">泛域名</span>
	 * @param domainName  <span class="en-US">Will check for Domain name</span>
	 *                    <span class="zh-CN">将要检查的域名</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	private static boolean matchDomain(final String matchDomain, final String domainName) {
		return matchDomain.startsWith("*")
				? domainName.toLowerCase().endsWith(matchDomain.substring(1).toLowerCase())
				: domainName.equalsIgnoreCase(matchDomain);
	}
}
