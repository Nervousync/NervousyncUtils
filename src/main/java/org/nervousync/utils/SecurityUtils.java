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

import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileInputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.nervousync.commons.Globals;
import org.nervousync.enumerations.crypto.CryptoMode;
import org.nervousync.exceptions.crypto.CryptoException;
import org.nervousync.exceptions.utils.DataInvalidException;
import org.nervousync.security.api.SecureAdapter;
import org.nervousync.security.digest.config.CRCConfig;
import org.nervousync.security.crypto.config.CipherConfig;
import org.nervousync.security.crypto.BaseCryptoAdapter;
import org.nervousync.security.crypto.impl.*;
import org.nervousync.security.digest.impl.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.ByteOrder;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;

/**
 * <h2 class="en-US">Security utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Initialize CRC/Blowfish/MD5/HmacMD5/DES/3DES/SHA/HmacSHA/AES/RSA/SM2/SM3/SM4/RC2/RC4 SecureAdapter</ul>
 *     <ul>Calculate CRC/MD5/HmacMD5/SHA/HmacSHA/SM3/HmacSM3/SHAKE128/SHAKE256 result</ul>
 * </span>
 * <h2 class="zh-CN">安全工具集</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>初始化CRC/Blowfish/MD5/HmacMD5/DES/3DES/SHA/HmacSHA/AES/RSA/SM2/SM3/SM4/RC2/RC4安全适配器</ul>
 *     <ul>计算CRC/MD5/HmacMD5/SHA/HmacSHA/SM3/HmacSM3/SHAKE128/SHAKE256结果</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.3 $ $Date: Jan 13, 2010 11:23:13 $
 */
public final class SecurityUtils {
	/**
	 * <span class="en-US">Multilingual supported logger instance</span>
	 * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(SecurityUtils.class);
	/**
	 * <span class="en-US">Registered CRC configure information</span>
	 * <span class="zh-CN">注册的CRC配置值映射表</span>
	 */
	private static final Map<String, CRCConfig> REGISTERED_CRC_CONFIG = new HashMap<>();

	static {
		Security.addProvider(new BouncyCastleProvider());
		SecurityUtils.registerConfig("CRC-3/GSM",
				new CRCConfig(3, 0x3, 0x0, 0x7, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-3/ROHC",
				new CRCConfig(3, 0x3, 0x7, 0x0, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-4/G-704",
				new CRCConfig(4, 0x3, 0x0, 0x0, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-4/INTERLAKEN",
				new CRCConfig(4, 0x3, 0xF, 0xF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-5/EPC-C1G2",
				new CRCConfig(5, 0x09, 0x09, 0x00, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-5/G-704",
				new CRCConfig(5, 0x15, 0x00, 0x00, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-5/USB",
				new CRCConfig(5, 0x05, 0x1F, 0x1F, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-6/CDMA2000-A",
				new CRCConfig(6, 0x27, 0x3F, 0x00, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-6/CDMA2000-B",
				new CRCConfig(6, 0x07, 0x3F, 0x00, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-6/DARC",
				new CRCConfig(6, 0x19, 0x00, 0x00, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-6/G-704",
				new CRCConfig(6, 0x03, 0x00, 0x00, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-6/GSM",
				new CRCConfig(6, 0x2F, 0x00, 0x3F, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-7/MMC",
				new CRCConfig(7, 0x09, 0x00, 0x00, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-7/ROHC",
				new CRCConfig(7, 0x4F, 0x7F, 0x00, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-7/UMTS",
				new CRCConfig(7, 0x45, 0x00, 0x00, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-8/AUTOSAR",
				new CRCConfig(8, 0x2F, 0xFF, 0xFF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-8/BLUETOOTH",
				new CRCConfig(8, 0xA7, 0x00, 0x00, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-8/CDMA2000",
				new CRCConfig(8, 0x9B, 0xFF, 0x00, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-8/DARC",
				new CRCConfig(8, 0x39, 0x00, 0x00, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-8/DVB-S2",
				new CRCConfig(8, 0xD5, 0x00, 0x00, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-8/GSM-A",
				new CRCConfig(8, 0x1D, 0x00, 0x00, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-8/GSM-B",
				new CRCConfig(8, 0x49, 0x00, 0xFF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-8/I-432-1",
				new CRCConfig(8, 0x07, 0x00, 0x55, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-8/I-CODE",
				new CRCConfig(8, 0x1D, 0xFD, 0x00, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-8/LTE",
				new CRCConfig(8, 0x9B, 0x00, 0x00, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-8/MAXIM-DOW",
				new CRCConfig(8, 0x31, 0x00, 0x00, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-8/MIFARE-MAD",
				new CRCConfig(8, 0x1D, 0xC7, 0x00, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-8/NRSC-5",
				new CRCConfig(8, 0x31, 0xFF, 0x00, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-8/OPENSAFETY",
				new CRCConfig(8, 0x2F, 0x00, 0x00, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-8/ROHC",
				new CRCConfig(8, 0x07, 0xFF, 0x00, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-8/SAE-J1850",
				new CRCConfig(8, 0x1D, 0xFF, 0xFF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-8/SMBUS",
				new CRCConfig(8, 0x07, 0x00, 0x00, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-8/TECH-3250",
				new CRCConfig(8, 0x1D, 0xFF, 0x00, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-8/WCDMA",
				new CRCConfig(8, 0x9B, 0x00, 0x00, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-10/ATM",
				new CRCConfig(10, 0x233, 0x000, 0x000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-10/CDMA2000",
				new CRCConfig(10, 0x3D9, 0x3FF, 0x000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-10/GSM",
				new CRCConfig(10, 0x175, 0x000, 0x3FF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-11/FLEXRAY",
				new CRCConfig(11, 0x385, 0x01A, 0x000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-11/UMTS",
				new CRCConfig(11, 0x307, 0x000, 0x000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-12/CDMA2000",
				new CRCConfig(12, 0xF13, 0xFFF, 0x000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-12/DECT",
				new CRCConfig(12, 0x80F, 0x000, 0x000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-12/GSM",
				new CRCConfig(12, 0xD31, 0x000, 0xFFF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-12/UMTS",
				new CRCConfig(12, 0x80F, 0x000, 0x000, Boolean.FALSE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-13/BBC",
				new CRCConfig(13, 0x1CF5, 0x0000, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-14/DARC",
				new CRCConfig(14, 0x0805, 0x0000, 0x0000, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-14/GSM",
				new CRCConfig(14, 0x202D, 0x0000, 0x3FFF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-15/CAN",
				new CRCConfig(15, 0x4599, 0x0000, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-15/MPT1327",
				new CRCConfig(15, 0x6815, 0x0000, 0x0001, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/ARC",
				new CRCConfig(16, 0x8005, 0x0000, 0x0000, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-16/CDMA2000",
				new CRCConfig(16, 0xC867, 0xFFFF, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/CMS",
				new CRCConfig(16, 0x8005, 0xFFFF, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/DDS-110",
				new CRCConfig(16, 0x8005, 0x800D, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/DECT-R",
				new CRCConfig(16, 0x0589, 0x0000, 0x0001, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/DECT-X",
				new CRCConfig(16, 0x0589, 0x0000, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/DNP",
				new CRCConfig(16, 0x3D65, 0x0000, 0xFFFF, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-16/EN-13757",
				new CRCConfig(16, 0x3D65, 0x0000, 0xFFFF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/GENIBUS",
				new CRCConfig(16, 0x1021, 0xFFFF, 0xFFFF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/GSM",
				new CRCConfig(16, 0x1021, 0x0000, 0xFFFF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/IBM-3740",
				new CRCConfig(16, 0x1021, 0xFFFF, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/IBM-SDLC",
				new CRCConfig(16, 0x1021, 0xFFFF, 0xFFFF, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-16/ISO-IEC-14443-3-A",
				new CRCConfig(16, 0x1021, 0xC6C6, 0x0000, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-16/KERMIT",
				new CRCConfig(16, 0x1021, 0x0000, 0x0000, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-16/LJ1200",
				new CRCConfig(16, 0x6F63, 0x0000, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/MAXIM-DOW",
				new CRCConfig(16, 0x8005, 0x0000, 0xFFFF, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-16/MCRF4XX",
				new CRCConfig(16, 0x1021, 0xFFFF, 0x0000, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-16/MODBUS",
				new CRCConfig(16, 0x8005, 0xFFFF, 0x0000, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-16/NRSC-5",
				new CRCConfig(16, 0x080B, 0xFFFF, 0x0000, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-16/OPENSAFETY-A",
				new CRCConfig(16, 0x5935, 0x0000, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/OPENSAFETY-B",
				new CRCConfig(16, 0x755B, 0x0000, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/PROFIBUS",
				new CRCConfig(16, 0x1DCF, 0xFFFF, 0xFFFF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/RIELLO",
				new CRCConfig(16, 0x1021, 0xB2AA, 0x0000, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-16/SPI-FUJITSU",
				new CRCConfig(16, 0x1021, 0x1D0F, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/T10-DIF",
				new CRCConfig(16, 0x8BB7, 0x0000, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/TELEDISK",
				new CRCConfig(16, 0xA097, 0x0000, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/TMS37157",
				new CRCConfig(16, 0x1021, 0x89EC, 0x0000, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-16/UMTS",
				new CRCConfig(16, 0x8005, 0x0000, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-16/USB",
				new CRCConfig(16, 0x8005, 0xFFFF, 0xFFFF, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-16/XMODEM",
				new CRCConfig(16, 0x1021, 0x0000, 0x0000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-17/CAN-FD",
				new CRCConfig(17, 0x1685B, 0x00000, 0x00000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-21/CAN-FD",
				new CRCConfig(21, 0x102899, 0x000000, 0x000000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-24/BLE",
				new CRCConfig(24, 0x00065B, 0x555555, 0x000000, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-24/FLEXRAY-A",
				new CRCConfig(24, 0x5D6DCB, 0xFEDCBA, 0x000000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-24/FLEXRAY-B",
				new CRCConfig(24, 0x5D6DCB, 0xABCDEF, 0x000000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-24/INTERLAKEN",
				new CRCConfig(24, 0x328B63, 0xFFFFFF, 0xFFFFFF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-24/LTE-A",
				new CRCConfig(24, 0x864CFB, 0x000000, 0x000000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-24/LTE-B",
				new CRCConfig(24, 0x800063, 0x000000, 0x000000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-24/OPENPGP",
				new CRCConfig(24, 0x864CFB, 0xB704CE, 0x000000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-24/OS-9",
				new CRCConfig(24, 0x800063, 0xFFFFFF, 0xFFFFFF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-30/CDMA",
				new CRCConfig(30, 0x2030B9C7, 0x3FFFFFFF, 0x3FFFFFFF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-31/PHILIPS",
				new CRCConfig(31, 0x04C11DB7, 0x7FFFFFFF, 0x7FFFFFFF, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-32/AIXM",
				new CRCConfig(32, 0x814141ABL, 0x00000000, 0x00000000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-32/AUTOSAR",
				new CRCConfig(32, 0xF4ACFB13L, 0xFFFFFFFFL, 0xFFFFFFFFL, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-32/BASE91-D",
				new CRCConfig(32, 0xA833982BL, 0xFFFFFFFFL, 0xFFFFFFFFL, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-32/BZIP2",
				new CRCConfig(32, 0x04C11DB7, 0xFFFFFFFFL, 0xFFFFFFFFL, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-32/CD-ROM-EDC",
				new CRCConfig(32, 0x8001801BL, 0x00000000, 0x00000000, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-32/CKSUM",
				new CRCConfig(32, 0x04C11DB7, 0x00000000, 0xFFFFFFFFL, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-32/ISCSI",
				new CRCConfig(32, 0x1EDC6F41, 0xFFFFFFFFL, 0xFFFFFFFFL, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-32/ISO-HDLC",
				new CRCConfig(32, 0x04C11DB7, 0xFFFFFFFFL, 0xFFFFFFFFL, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-32/JAMCRC",
				new CRCConfig(32, 0x04C11DB7, 0xFFFFFFFFL, 0x00000000, Boolean.TRUE, Boolean.TRUE));
		SecurityUtils.registerConfig("CRC-32/MPEG-2",
				new CRCConfig(32, 0x04C11DB7, 0xFFFFFFFFL, 0x00000000, Boolean.FALSE, Boolean.FALSE));
		SecurityUtils.registerConfig("CRC-32/XFER",
				new CRCConfig(32, 0x000000AF, 0x00000000, 0x00000000, Boolean.FALSE, Boolean.FALSE));
		LOGGER.info("Registered_CRC_Algorithm",
				String.join(",", new ArrayList<>(REGISTERED_CRC_CONFIG.keySet())));
	}

	/**
	 * <h3 class="en-US">Private constructor for SecurityUtils</h3>
	 * <h3 class="zh-CN">安全工具集的私有构造方法</h3>
	 */
	private SecurityUtils() {
	}

	/**
	 * <h3 class="en-US">Register CRC configure information</h3>
	 * <h3 class="zh-CN">注册CRC配置信息</h3>
	 *
	 * @param algorithm <span class="en-US">Algorithm name</span>
	 *                  <span class="zh-CN">算法名称</span>
	 * @param crcConfig <span class="en-US">CRC configure information</span>
	 *                  <span class="zh-CN">CRC配置信息</span>
	 */
	public static void registerConfig(final String algorithm, final CRCConfig crcConfig) {
		if (StringUtils.isEmpty(algorithm) || crcConfig == null) {
			LOGGER.error("Parameter_Null_Register_Security_Error");
			return;
		}
		if (crcConfig.getBit() > 32) {
			LOGGER.error("Lager_CRC_Security_Error");
			return;
		}
		if (REGISTERED_CRC_CONFIG.containsKey(algorithm)) {
			LOGGER.warn("Override_Config_Register_Security_Warn", algorithm);
		}
		REGISTERED_CRC_CONFIG.put(algorithm, crcConfig);
	}

	/**
	 * <h3 class="en-US">Registered CRC algorithm name list</h3>
	 * <h3 class="zh-CN">已注册的CRC算法名列表</h3>
	 *
	 * @return <span class="en-US">CRC algorithm name list</span>
	 * <span class="zh-CN">CRC算法名列表</span>
	 */
	public static List<String> registeredCRC() {
		return new ArrayList<>(REGISTERED_CRC_CONFIG.keySet());
	}

	/**
	 * <h3 class="en-US">Initialize CRC secure provider</h3>
	 * <h3 class="zh-CN">初始化CRC安全适配器实例对象</h3>
	 *
	 * @param algorithm <span class="en-US">Algorithm name</span>
	 *                  <span class="zh-CN">算法名称</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If CRC algorithm didn't find</span>
	 *                         <span class="zh-CN">如果CRC算法未找到</span>
	 */
	public static SecureAdapter CRC(final String algorithm) throws CryptoException {
		if (REGISTERED_CRC_CONFIG.containsKey(algorithm)) {
			return new CRCDigestAdapterImpl(REGISTERED_CRC_CONFIG.get(algorithm));
		}
		throw new CryptoException(0x00000015000DL, "Unknown_Algorithm_Digits_Error", algorithm);
	}

	/**
	 * <h3 class="en-US">Retrieve registered CRC configure information</h3>
	 * <h3 class="zh-CN">查找已注册的CRC配置信息</h3>
	 *
	 * @param algorithm <span class="en-US">Algorithm name</span>
	 *                  <span class="zh-CN">算法名称</span>
	 * @return <span class="en-US">CRC configure information instance or null if not found</span>
	 * <span class="zh-CN">找到的CRC配置信息实例对象，如果未找到返回<code>null</code></span>
	 */
	public static CRCConfig crcConfig(final String algorithm) {
		return REGISTERED_CRC_CONFIG.get(algorithm);
	}

	/**
	 * <h3 class="en-US">Convert crc result from byte arrays to string</h3>
	 * <h3 class="zh-CN">将CRC结果字节数组转换为字符串</h3>
	 *
	 * @param algorithm <span class="en-US">Algorithm name</span>
	 *                  <span class="zh-CN">算法名称</span>
	 * @param result    <span class="en-US">CRC result byte array</span>
	 *                  <span class="zh-CN">CRC结果字节数组</span>
	 * @return <span class="en-US">Converted string result</span>
	 * <span class="zh-CN">转换后的结果字符串</span>
	 * @throws CryptoException <span class="en-US">If CRC algorithm didn't find</span>
	 *                         <span class="zh-CN">如果CRC算法未找到</span>
	 */
	public static String CRCResult(final String algorithm, final byte[] result) throws DataInvalidException, CryptoException {
		long crc = RawUtils.readLong(result, ByteOrder.LITTLE_ENDIAN);
		return Optional.ofNullable(SecurityUtils.crcConfig(algorithm))
				.map(crcConfig -> {
					StringBuilder stringBuilder = new StringBuilder(Long.toString(crc, 16));
					while (stringBuilder.length() < crcConfig.getOutLength()) {
						stringBuilder.insert(0, "0");
					}
					return "0x" + stringBuilder;
				})
				.orElseThrow(() -> new CryptoException(0x00000015000DL, "Unknown_Algorithm_Digits_Error", algorithm));
	}
	/*
	 * Digest Methods
	 */

	/**
	 * <h3 class="en-US">Initialize MD5 secure provider</h3>
	 * <h3 class="zh-CN">初始化MD5安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	@Deprecated
	public static SecureAdapter MD5() throws CryptoException {
		return new MD5DigestAdapterImpl();
	}

	/**
	 * <h3 class="en-US">Calculate MD5 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的MD5值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	@Deprecated
	public static byte[] MD5(final Object source) {
		try {
			return calculate(source, MD5());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "MD5");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize HmacMD5 secure provider</h3>
	 * <h3 class="zh-CN">初始化HmacMD5安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter HmacMD5(final byte[] keyBytes) throws CryptoException {
		return new MD5DigestAdapterImpl(keyBytes);
	}

	/**
	 * <h3 class="en-US">Calculate HmacMD5 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的HmacMD5值</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @param source   <span class="en-US">source object</span>
	 *                 <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] HmacMD5(final byte[] keyBytes, final Object source) {
		try {
			return calculate(source, HmacMD5(keyBytes));
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "HmacMD5");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SHA1 secure provider</h3>
	 * <h3 class="zh-CN">初始化SHA1安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	@Deprecated
	public static SecureAdapter SHA1() throws CryptoException {
		return new SHA1DigestAdapterImpl();
	}

	/**
	 * <h3 class="en-US">Calculate SHA1 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的SHA1值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	@Deprecated
	public static byte[] SHA1(final Object source) {
		try {
			return calculate(source, SHA1());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "SHA1");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize HmacSHA1 secure provider</h3>
	 * <h3 class="zh-CN">初始化HmacSHA1安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter HmacSHA1(final byte[] keyBytes) throws CryptoException {
		return new SHA1DigestAdapterImpl(keyBytes);
	}

	/**
	 * <h3 class="en-US">Calculate HmacSHA1 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的HmacSHA1值</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @param source   <span class="en-US">source object</span>
	 *                 <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] HmacSHA1(final byte[] keyBytes, final Object source) {
		try {
			return calculate(source, HmacSHA1(keyBytes));
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "HmacSHA1");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SHA-224 secure provider</h3>
	 * <h3 class="zh-CN">初始化SHA-224安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SHA224() throws CryptoException {
		return new SHA2DigestAdapterImpl("SHA-224", new byte[0]);
	}

	/**
	 * <h3 class="en-US">Calculate SHA224 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的SHA224值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] SHA224(final Object source) {
		try {
			return calculate(source, SHA224());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "SHA224");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize HmacSHA224 secure provider</h3>
	 * <h3 class="zh-CN">初始化HmacSHA224安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter HmacSHA224(final byte[] keyBytes) throws CryptoException {
		return new SHA2DigestAdapterImpl("SHA-224/HMAC", keyBytes);
	}

	/**
	 * <h3 class="en-US">Calculate HmacSHA224 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的HmacSHA224值</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @param source   <span class="en-US">source object</span>
	 *                 <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] HmacSHA224(final byte[] keyBytes, final Object source) {
		try {
			return calculate(source, HmacSHA224(keyBytes));
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "HmacSHA224");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SHA256 secure provider</h3>
	 * <h3 class="zh-CN">初始化SHA256安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SHA256() throws CryptoException {
		return new SHA2DigestAdapterImpl("SHA-256", new byte[0]);
	}

	/**
	 * <h3 class="en-US">Calculate SHA256 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的SHA256值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] SHA256(final Object source) {
		try {
			return calculate(source, SHA256());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "SHA256");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize HmacSHA256 secure provider</h3>
	 * <h3 class="zh-CN">初始化HmacSHA256安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter HmacSHA256(final byte[] keyBytes) throws CryptoException {
		return new SHA2DigestAdapterImpl("SHA-256/HMAC", keyBytes);
	}

	/**
	 * <h3 class="en-US">Calculate HmacSHA256 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的HmacSHA256值</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @param source   <span class="en-US">source object</span>
	 *                 <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] HmacSHA256(final byte[] keyBytes, final Object source) {
		try {
			return calculate(source, HmacSHA256(keyBytes));
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "HmacSHA256");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SHA384 secure provider</h3>
	 * <h3 class="zh-CN">初始化SHA384安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SHA384() throws CryptoException {
		return new SHA2DigestAdapterImpl("SHA-384", new byte[0]);
	}

	/**
	 * <h3 class="en-US">Calculate SHA384 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的SHA384值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] SHA384(final Object source) {
		try {
			return calculate(source, SHA384());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "SHA384");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize HmacSHA384 secure provider</h3>
	 * <h3 class="zh-CN">初始化HmacSHA384安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter HmacSHA384(final byte[] keyBytes) throws CryptoException {
		return new SHA2DigestAdapterImpl("SHA-384/HMAC", keyBytes);
	}

	/**
	 * <h3 class="en-US">Calculate HmacSHA384 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的HmacSHA384值</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @param source   <span class="en-US">source object</span>
	 *                 <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] HmacSHA384(final byte[] keyBytes, final Object source) {
		try {
			return calculate(source, HmacSHA384(keyBytes));
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "HmacSHA384");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SHA512 secure provider</h3>
	 * <h3 class="zh-CN">初始化SHA512安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SHA512() throws CryptoException {
		return new SHA2DigestAdapterImpl("SHA-512", new byte[0]);
	}

	/**
	 * <h3 class="en-US">Calculate SHA512 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的SHA512值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] SHA512(final Object source) {
		try {
			return calculate(source, SHA512());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "SHA512");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize HmacSHA512 secure provider</h3>
	 * <h3 class="zh-CN">初始化HmacSHA512安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter HmacSHA512(final byte[] keyBytes) throws CryptoException {
		return new SHA2DigestAdapterImpl("SHA-512/HMAC", keyBytes);
	}

	/**
	 * <h3 class="en-US">Calculate HmacSHA512 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的HmacSHA512值</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @param source   <span class="en-US">source object</span>
	 *                 <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] HmacSHA512(final byte[] keyBytes, final Object source) {
		try {
			return calculate(source, HmacSHA512(keyBytes));
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "HmacSHA512");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SHA512/224 secure provider</h3>
	 * <h3 class="zh-CN">初始化SHA512/224安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SHA512_224() throws CryptoException {
		return new SHA2DigestAdapterImpl("SHA-512/224", new byte[0]);
	}

	/**
	 * <h3 class="en-US">Calculate SHA512/224 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的SHA512/224值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] SHA512_224(final Object source) {
		try {
			return calculate(source, SHA512_224());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "SHA512-224");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize HmacSHA512/224 secure provider</h3>
	 * <h3 class="zh-CN">初始化HmacSHA512/224安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter HmacSHA512_224(final byte[] keyBytes) throws CryptoException {
		return new SHA2DigestAdapterImpl("SHA-512/224/HMAC", keyBytes);
	}

	/**
	 * <h3 class="en-US">Calculate HmacSHA512/224 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的HmacSHA512/224值</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @param source   <span class="en-US">source object</span>
	 *                 <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] HmacSHA512_224(final byte[] keyBytes, final Object source) {
		try {
			return calculate(source, HmacSHA512_224(keyBytes));
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "HmacSHA512-224");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SHA512/256 secure provider</h3>
	 * <h3 class="zh-CN">初始化SHA512/256安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SHA512_256() throws CryptoException {
		return new SHA2DigestAdapterImpl("SHA-512/256", new byte[0]);
	}

	/**
	 * <h3 class="en-US">Calculate SHA512/256 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的SHA512/256值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] SHA512_256(final Object source) {
		try {
			return calculate(source, SHA512_256());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "SHA512-256");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize HmacSHA512/256 secure provider</h3>
	 * <h3 class="zh-CN">初始化HmacSHA512/256安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter HmacSHA512_256(final byte[] keyBytes) throws CryptoException {
		return new SHA2DigestAdapterImpl("SHA-512/256/HMAC", keyBytes);
	}

	/**
	 * <h3 class="en-US">Calculate HmacSHA512/256 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的HmacSHA512/256值</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @param source   <span class="en-US">source object</span>
	 *                 <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] HmacSHA512_256(final byte[] keyBytes, final Object source) {
		try {
			return calculate(source, HmacSHA512_256(keyBytes));
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "HmacSHA512-256");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SHA3-224 secure provider</h3>
	 * <h3 class="zh-CN">初始化SHA3-224安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SHA3_224() throws CryptoException {
		return new SHA3DigestAdapterImpl("SHA3-224");
	}

	/**
	 * <h3 class="en-US">Calculate SHA3-224 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的SHA3-224值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] SHA3_224(final Object source) {
		try {
			return calculate(source, SHA3_224());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "SHA3-224");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize HmacSHA3-224 secure provider</h3>
	 * <h3 class="zh-CN">初始化HmacSHA3-224安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter HmacSHA3_224(final byte[] keyBytes) throws CryptoException {
		return new SHA3DigestAdapterImpl("SHA3-224/HMAC", keyBytes);
	}

	/**
	 * <h3 class="en-US">Calculate HmacSHA3-224 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的HmacSHA3-224值</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @param source   <span class="en-US">source object</span>
	 *                 <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] HmacSHA3_224(final byte[] keyBytes, final Object source) {
		try {
			return calculate(source, HmacSHA3_224(keyBytes));
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "HmacSHA3-224");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SHA3-256 secure provider</h3>
	 * <h3 class="zh-CN">初始化SHA3-256安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SHA3_256() throws CryptoException {
		return new SHA3DigestAdapterImpl("SHA3-256");
	}

	/**
	 * <h3 class="en-US">Calculate SHA3-256 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的SHA3-256值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] SHA3_256(final Object source) {
		try {
			return calculate(source, SHA3_256());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "SHA3-256");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize HmacSHA3-256 secure provider</h3>
	 * <h3 class="zh-CN">初始化HmacSHA3-256安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter HmacSHA3_256(final byte[] keyBytes) throws CryptoException {
		return new SHA3DigestAdapterImpl("SHA3-256/HMAC", keyBytes);
	}

	/**
	 * <h3 class="en-US">Calculate HmacSHA3-256 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的HmacSHA3-256值</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @param source   <span class="en-US">source object</span>
	 *                 <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] HmacSHA3_256(final byte[] keyBytes, final Object source) {
		try {
			return calculate(source, HmacSHA3_256(keyBytes));
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "HmacSHA3-256");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SHA3-384 secure provider</h3>
	 * <h3 class="zh-CN">初始化SHA3-384安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SHA3_384() throws CryptoException {
		return new SHA3DigestAdapterImpl("SHA3-384");
	}

	/**
	 * <h3 class="en-US">Calculate SHA3-384 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的SHA3-384值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] SHA3_384(final Object source) {
		try {
			return calculate(source, SHA3_384());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "SHA3-384");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize HmacSHA3-384 secure provider</h3>
	 * <h3 class="zh-CN">初始化HmacSHA3-384安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter HmacSHA3_384(final byte[] keyBytes) throws CryptoException {
		return new SHA3DigestAdapterImpl("SHA3-384/HMAC", keyBytes);
	}

	/**
	 * <h3 class="en-US">Calculate HmacSHA3-384 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的HmacSHA3-384值</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @param source   <span class="en-US">source object</span>
	 *                 <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] HmacSHA3_384(final byte[] keyBytes, final Object source) {
		try {
			return calculate(source, HmacSHA3_384(keyBytes));
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "HmacSHA3-384");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SHA3-512 secure provider</h3>
	 * <h3 class="zh-CN">初始化SHA3-512安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SHA3_512() throws CryptoException {
		return new SHA3DigestAdapterImpl("SHA3-512");
	}

	/**
	 * <h3 class="en-US">Calculate SHA3-512 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的SHA3-512值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] SHA3_512(final Object source) {
		try {
			return calculate(source, SHA3_512());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "SHA3-512");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize HmacSHA3-512 secure provider</h3>
	 * <h3 class="zh-CN">初始化HmacSHA3-512安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter HmacSHA3_512(final byte[] keyBytes) throws CryptoException {
		return new SHA3DigestAdapterImpl("SHA3-512/HMAC", keyBytes);
	}

	/**
	 * <h3 class="en-US">Calculate HmacSHA3-512 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的HmacSHA3-512值</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @param source   <span class="en-US">source object</span>
	 *                 <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] HmacSHA3_512(final byte[] keyBytes, final Object source) {
		try {
			return calculate(source, HmacSHA3_512(keyBytes));
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "HmacSHA3-512");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SHAKE128 secure provider</h3>
	 * <h3 class="zh-CN">初始化SHAKE128安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SHAKE128() throws CryptoException {
		return new SHA3DigestAdapterImpl("SHAKE128");
	}

	/**
	 * <h3 class="en-US">Calculate SHAKE128 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的SHAKE128值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] SHAKE128(final Object source) {
		try {
			return calculate(source, SHAKE128());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "SHAKE128");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SHAKE256 secure provider</h3>
	 * <h3 class="zh-CN">初始化SHAKE256安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SHAKE256() throws CryptoException {
		return new SHA3DigestAdapterImpl("SHAKE256");
	}

	/**
	 * <h3 class="en-US">Calculate SHAKE256 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的SHAKE256值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] SHAKE256(final Object source) {
		try {
			return calculate(source, SHAKE256());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "SHAKE256");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SM3 secure provider</h3>
	 * <h3 class="zh-CN">初始化SM3安全适配器实例对象</h3>
	 *
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SM3() throws CryptoException {
		return new SM3DigestAdapterImpl();
	}

	/**
	 * <h3 class="en-US">Calculate SM3 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的SM3值</h3>
	 *
	 * @param source <span class="en-US">source object</span>
	 *               <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] SM3(final Object source) {
		try {
			return calculate(source, SM3());
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "SM3");
			}
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize HmacSM3 secure provider</h3>
	 * <h3 class="zh-CN">初始化HmacSM3安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter HmacSM3(final byte[] keyBytes) throws CryptoException {
		return new SM3DigestAdapterImpl(keyBytes);
	}

	/**
	 * <h3 class="en-US">Calculate HmacSM3 value of the given source object</h3>
	 * <h3 class="zh-CN">计算给定的原始数据对象的HmacSM3值</h3>
	 *
	 * @param keyBytes <span class="en-US">HMAC key bytes</span>
	 *                 <span class="zh-CN">HMAC密钥字节数组</span>
	 * @param source   <span class="en-US">source object</span>
	 *                 <span class="zh-CN">原始数据对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 */
	public static byte[] HmacSM3(final byte[] keyBytes, final Object source) {
		try {
			return calculate(source, HmacSM3(keyBytes));
		} catch (CryptoException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate_Value_Security_Error", e, "HmacSM3");
			}
			return new byte[0];
		}
	}
	/*
	 *	Symmetric methods
	 */

	/**
	 * <h3 class="en-US">Initialize Blowfish encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化Blowfish加密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter BlowfishEncryptor(final byte[] keyBytes) throws CryptoException {
		return BlowfishEncryptor("CBC", "PKCS7Padding", keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize Blowfish encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化Blowfish加密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter BlowfishEncryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return new BlowfishCryptoAdapterImpl(new CipherConfig("Blowfish", mode, padding), CryptoMode.ENCRYPT, keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize Blowfish encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化Blowfish解密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter BlowfishDecryptor(final byte[] keyBytes) throws CryptoException {
		return BlowfishDecryptor("CBC", "PKCS7Padding", keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize Blowfish encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化Blowfish解密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter BlowfishDecryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return new BlowfishCryptoAdapterImpl(new CipherConfig("Blowfish", mode, padding), CryptoMode.DECRYPT, keyBytes);
	}

	/**
	 * <h3 class="en-US">Generate Blowfish key bytes</h3>
	 * <h3 class="zh-CN">生成Blowfish密钥字节数组</h3>
	 *
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 */
	public static byte[] BlowfishKey() {
		try {
			return symmetricKey("Blowfish", 56, Globals.DEFAULT_VALUE_STRING);
		} catch (CryptoException e) {
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize DES encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化DES加密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter DESEncryptor(final byte[] keyBytes) throws CryptoException {
		return DESEncryptor("CBC", "PKCS5Padding", keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize DES encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化DES加密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter DESEncryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return new DESCryptoAdapterImpl(new CipherConfig("DES", mode, padding), CryptoMode.ENCRYPT, keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize DES decryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化DES解密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter DESDecryptor(final byte[] keyBytes) throws CryptoException {
		return DESDecryptor("CBC", "PKCS5Padding", keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize DES decryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化DES解密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter DESDecryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return new DESCryptoAdapterImpl(new CipherConfig("DES", mode, padding), CryptoMode.DECRYPT, keyBytes);
	}

	/**
	 * <h3 class="en-US">Generate DES key bytes</h3>
	 * <h3 class="zh-CN">生成DES密钥字节数组</h3>
	 *
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 */
	public static byte[] DESKey() {
		try {
			return symmetricKey("DES", Globals.DEFAULT_VALUE_INT, Globals.DEFAULT_VALUE_STRING);
		} catch (CryptoException e) {
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize TripleDES encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化3DES加密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter TripleDESEncryptor(final byte[] keyBytes) throws CryptoException {
		return TripleDESEncryptor("CBC", "PKCS5Padding", keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize TripleDES encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化3DES加密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter TripleDESEncryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return new TripleDESCryptoAdapterImpl(new CipherConfig("DESede", mode, padding),
				CryptoMode.ENCRYPT, keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize TripleDES decryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化3DES解密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter TripleDESDecryptor(final byte[] keyBytes) throws CryptoException {
		return TripleDESDecryptor("CBC", "PKCS5Padding", keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize TripleDES decryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化3DES解密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter TripleDESDecryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return new TripleDESCryptoAdapterImpl(new CipherConfig("DESede", mode, padding),
				CryptoMode.DECRYPT, keyBytes);
	}

	/**
	 * <h3 class="en-US">Generate TripleDES key bytes</h3>
	 * <h3 class="zh-CN">生成3DES密钥字节数组</h3>
	 *
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 */
	public static byte[] TripleDESKey() {
		try {
			return symmetricKey("DESede", Globals.DEFAULT_VALUE_INT, Globals.DEFAULT_VALUE_STRING);
		} catch (CryptoException e) {
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize SM4 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化SM4加密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SM4Encryptor(final byte[] keyBytes) throws CryptoException {
		return SM4Encryptor("CBC", "PKCS5Padding", keyBytes, "SHA1PRNG");
	}

	/**
	 * <h3 class="en-US">Initialize SM4 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化SM4加密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8", "CFB128", "OFB128"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SM4Encryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return SM4Encryptor(mode, padding, keyBytes, "SHA1PRNG");
	}

	/**
	 * <h3 class="en-US">Initialize SM4 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化SM4加密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8", "CFB128", "OFB128"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode            <span class="en-US">Cipher Mode</span>
	 *                        <span class="zh-CN">分组密码模式</span>
	 * @param padding         <span class="en-US">Padding Mode</span>
	 *                        <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes        <span class="en-US">key bytes</span>
	 *                        <span class="zh-CN">密钥字节数组</span>
	 * @param randomAlgorithm <span class="en-US">Random algorithm</span>
	 *                        <span class="zh-CN">随机数算法</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SM4Encryptor(final String mode, final String padding, final byte[] keyBytes,
	                                         final String randomAlgorithm) throws CryptoException {
		return new SM4CryptoAdapterImpl(new CipherConfig("SM4", mode, padding),
				CryptoMode.ENCRYPT, keyBytes, randomAlgorithm);
	}

	/**
	 * <h3 class="en-US">Initialize SM4 decryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化SM4解密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SM4Decryptor(final byte[] keyBytes) throws CryptoException {
		return SM4Decryptor("CBC", "PKCS5Padding", keyBytes, "SHA1PRNG");
	}

	/**
	 * <h3 class="en-US">Initialize SM4 decryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化SM4解密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8", "CFB128", "OFB128"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SM4Decryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return SM4Decryptor(mode, padding, keyBytes, "SHA1PRNG");
	}

	/**
	 * <h3 class="en-US">Initialize SM4 decryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化SM4解密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8", "CFB128", "OFB128"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode            <span class="en-US">Cipher Mode</span>
	 *                        <span class="zh-CN">分组密码模式</span>
	 * @param padding         <span class="en-US">Padding Mode</span>
	 *                        <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes        <span class="en-US">key bytes</span>
	 *                        <span class="zh-CN">密钥字节数组</span>
	 * @param randomAlgorithm <span class="en-US">Random algorithm</span>
	 *                        <span class="zh-CN">随机数算法</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SM4Decryptor(final String mode, final String padding, final byte[] keyBytes,
	                                         final String randomAlgorithm) throws CryptoException {
		return new SM4CryptoAdapterImpl(new CipherConfig("SM4", mode, padding),
				CryptoMode.DECRYPT, keyBytes, randomAlgorithm);
	}

	/**
	 * <h3 class="en-US">Generate SM4 key bytes</h3>
	 * <h3 class="zh-CN">生成SM4密钥字节数组</h3>
	 *
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 */
	public static byte[] SM4Key() {
		try {
			return symmetricKey("SM4", 128, Globals.DEFAULT_VALUE_STRING);
		} catch (CryptoException e) {
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize RC2 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC2加密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC2Encryptor(final byte[] keyBytes) throws CryptoException {
		return RC2Encryptor("CBC", "PKCS7Padding", keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize RC2 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC2加密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC2Encryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return new RC2CryptoAdapterImpl(new CipherConfig("RC2", mode, padding), CryptoMode.ENCRYPT, keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize RC2 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC2解密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC2Decryptor(final byte[] keyBytes) throws CryptoException {
		return RC2Decryptor("CBC", "PKCS7Padding", keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize RC2 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC2解密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC2Decryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return new RC2CryptoAdapterImpl(new CipherConfig("RC2", mode, padding), CryptoMode.DECRYPT, keyBytes);
	}

	/**
	 * <h3 class="en-US">Generate RC2 key bytes</h3>
	 * <h3 class="zh-CN">生成RC2密钥字节数组</h3>
	 *
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 */
	public static byte[] RC2Key() {
		try {
			return symmetricKey("RC2", 128, Globals.DEFAULT_VALUE_STRING);
		} catch (CryptoException e) {
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize RC4 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC4加密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC4Encryptor(final byte[] keyBytes) throws CryptoException {
		return RC4Encryptor(keyBytes, "SHA1PRNG");
	}

	/**
	 * <h3 class="en-US">Initialize RC4 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC4加密安全适配器实例对象</h3>
	 *
	 * @param keyBytes        <span class="en-US">key bytes</span>
	 *                        <span class="zh-CN">密钥字节数组</span>
	 * @param randomAlgorithm <span class="en-US">Random algorithm</span>
	 *                        <span class="zh-CN">随机数算法</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC4Encryptor(final byte[] keyBytes, final String randomAlgorithm)
			throws CryptoException {
		return new RC4CryptoAdapterImpl(new CipherConfig("RC4", Globals.DEFAULT_VALUE_STRING, Globals.DEFAULT_VALUE_STRING),
				CryptoMode.ENCRYPT, keyBytes, randomAlgorithm);
	}

	/**
	 * <h3 class="en-US">Initialize RC4 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC4解密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC4Decryptor(final byte[] keyBytes) throws CryptoException {
		return RC4Decryptor(keyBytes, "SHA1PRNG");
	}

	/**
	 * <h3 class="en-US">Initialize RC4 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC4解密安全适配器实例对象</h3>
	 *
	 * @param keyBytes        <span class="en-US">key bytes</span>
	 *                        <span class="zh-CN">密钥字节数组</span>
	 * @param randomAlgorithm <span class="en-US">Random algorithm</span>
	 *                        <span class="zh-CN">随机数算法</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC4Decryptor(final byte[] keyBytes, final String randomAlgorithm)
			throws CryptoException {
		return new RC4CryptoAdapterImpl(new CipherConfig("RC4", Globals.DEFAULT_VALUE_STRING, Globals.DEFAULT_VALUE_STRING),
				CryptoMode.DECRYPT, keyBytes, randomAlgorithm);
	}

	/**
	 * <h3 class="en-US">Generate RC4 key bytes</h3>
	 * <h3 class="zh-CN">生成RC4密钥字节数组</h3>
	 *
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 */
	public static byte[] RC4Key() {
		try {
			return symmetricKey("RC4", 128, Globals.DEFAULT_VALUE_STRING);
		} catch (CryptoException e) {
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize RC5 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC5加密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC5Encryptor(final byte[] keyBytes) throws CryptoException {
		return RC5Encryptor("CBC", "PKCS5Padding", keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize RC5 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC5加密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC5Encryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return new RC5CryptoAdapterImpl(new CipherConfig("RC5", mode, padding), CryptoMode.ENCRYPT, keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize RC5 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC5解密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC5Decryptor(final byte[] keyBytes) throws CryptoException {
		return RC5Decryptor("CBC", "PKCS5Padding", keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize RC5 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC5解密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC5Decryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return new RC5CryptoAdapterImpl(new CipherConfig("RC5", mode, padding), CryptoMode.DECRYPT, keyBytes);
	}

	/**
	 * <h3 class="en-US">Generate RC5 key bytes</h3>
	 * <h3 class="zh-CN">生成RC5密钥字节数组</h3>
	 *
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 */
	public static byte[] RC5Key() {
		try {
			return symmetricKey("RC5", 128, Globals.DEFAULT_VALUE_STRING);
		} catch (CryptoException e) {
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Initialize RC6 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC6加密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC6Encryptor(final byte[] keyBytes) throws CryptoException {
		return RC6Encryptor("CBC", "PKCS5Padding", keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize RC6 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC6加密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC6Encryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return new RC6CryptoAdapterImpl(new CipherConfig("RC6", mode, padding), CryptoMode.ENCRYPT, keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize RC6 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC6解密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC6Decryptor(final byte[] keyBytes) throws CryptoException {
		return RC6Decryptor("CBC", "PKCS5Padding", keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize RC6 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RC6解密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RC6Decryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return new RC6CryptoAdapterImpl(new CipherConfig("RC6", mode, padding), CryptoMode.DECRYPT, keyBytes);
	}

	/**
	 * <h3 class="en-US">Generate RC6 key bytes</h3>
	 * <h3 class="zh-CN">生成RC6密钥字节数组</h3>
	 *
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 */
	public static byte[] RC6Key() {
		try {
			return symmetricKey("RC6", 128, Globals.DEFAULT_VALUE_STRING);
		} catch (CryptoException e) {
			return new byte[0];
		}
	}

	/*
	 * Asymmetric methods
	 */

	/**
	 * <h3 class="en-US">Initialize RSA encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RSA加密安全适配器实例对象</h3>
	 *
	 * @param publicKey <span class="en-US">Public Key instance</span>
	 *                  <span class="zh-CN">公钥证书实例对象</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RSAEncryptor(final Key publicKey) throws CryptoException {
		return RSAEncryptor("PKCS1Padding", publicKey);
	}

	/**
	 * <h3 class="en-US">Initialize RSA encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RSA加密安全适配器实例对象</h3>
	 * <span>
	 * padding:  "NoPadding", "PKCS1Padding", "OAEPWithSHA-1AndMGF1Padding",
	 * "OAEPWithSHA-224AndMGF1Padding", "OAEPWithSHA-256AndMGF1Padding",
	 * "OAEPWithSHA-384AndMGF1Padding", "OAEPWithSHA-512AndMGF1Padding",
	 * "OAEPWithSHA3-224AndMGF1Padding", "OAEPWithSHA3-256AndMGF1Padding",
	 * "OAEPWithSHA3-384AndMGF1Padding", "OAEPWithSHA3-512AndMGF1Padding"
	 * </span>
	 *
	 * @param padding   <span class="en-US">Padding Mode</span>
	 *                  <span class="zh-CN">数据填充模式</span>
	 * @param publicKey <span class="en-US">Public Key instance</span>
	 *                  <span class="zh-CN">公钥证书实例对象</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RSAEncryptor(final String padding, final Key publicKey) throws CryptoException {
		return new RSACryptoAdapterImpl(new CipherConfig("RSA", "ECB", padding),
				CryptoMode.ENCRYPT, new BaseCryptoAdapter.CipherKey(publicKey));
	}

	/**
	 * <h3 class="en-US">Initialize RSA decryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RSA解密安全适配器实例对象</h3>
	 *
	 * @param privateKey <span class="en-US">Private Key instance</span>
	 *                   <span class="zh-CN">私钥证书实例对象</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RSADecryptor(final Key privateKey) throws CryptoException {
		return RSADecryptor("PKCS1Padding", privateKey);
	}

	/**
	 * <h3 class="en-US">Initialize RSA decryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化RSA解密安全适配器实例对象</h3>
	 * <span>
	 * padding:  "NoPadding", "PKCS1Padding", "OAEPWithSHA-1AndMGF1Padding",
	 * "OAEPWithSHA-224AndMGF1Padding", "OAEPWithSHA-256AndMGF1Padding",
	 * "OAEPWithSHA-384AndMGF1Padding", "OAEPWithSHA-512AndMGF1Padding",
	 * "OAEPWithSHA3-224AndMGF1Padding", "OAEPWithSHA3-256AndMGF1Padding",
	 * "OAEPWithSHA3-384AndMGF1Padding", "OAEPWithSHA3-512AndMGF1Padding"
	 * </span>
	 *
	 * @param padding    <span class="en-US">Padding Mode</span>
	 *                   <span class="zh-CN">数据填充模式</span>
	 * @param privateKey <span class="en-US">Private Key instance</span>
	 *                   <span class="zh-CN">私钥证书实例对象</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RSADecryptor(final String padding, final Key privateKey) throws CryptoException {
		return new RSACryptoAdapterImpl(new CipherConfig("RSA", "ECB", padding),
				CryptoMode.DECRYPT, new BaseCryptoAdapter.CipherKey(privateKey));
	}

	/**
	 * <h3 class="en-US">Initialize RSA signer secure provider</h3>
	 * <h3 class="zh-CN">初始化RSA签名安全适配器实例对象</h3>
	 *
	 * @param privateKey <span class="en-US">Private Key instance</span>
	 *                   <span class="zh-CN">私钥证书实例对象</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RSASigner(final PrivateKey privateKey) throws CryptoException {
		return RSASigner("SHA256withRSA", privateKey);
	}

	/**
	 * <h3 class="en-US">Initialize RSA signer secure provider</h3>
	 * <h3 class="zh-CN">初始化RSA签名安全适配器实例对象</h3>
	 *
	 * @param algorithm  <span class="en-US">Signature algorithm name</span>
	 *                   <span class="zh-CN">签名算法名称</span>
	 * @param privateKey <span class="en-US">Private Key instance</span>
	 *                   <span class="zh-CN">私钥证书实例对象</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RSASigner(final String algorithm, final PrivateKey privateKey) throws CryptoException {
		return new RSACryptoAdapterImpl(
				new CipherConfig(algorithm, Globals.DEFAULT_VALUE_STRING, Globals.DEFAULT_VALUE_STRING),
				CryptoMode.SIGNATURE, new BaseCryptoAdapter.CipherKey(privateKey));
	}

	/**
	 * <h3 class="en-US">Initialize RSA signature verifier secure provider</h3>
	 * <h3 class="zh-CN">初始化RSA签名验证安全适配器实例对象</h3>
	 *
	 * @param publicKey <span class="en-US">Public Key instance</span>
	 *                  <span class="zh-CN">公钥证书实例对象</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RSAVerifier(final PublicKey publicKey) throws CryptoException {
		return RSAVerifier("SHA256withRSA", publicKey);
	}

	/**
	 * <h3 class="en-US">Initialize RSA signature verifier secure provider</h3>
	 * <h3 class="zh-CN">初始化RSA签名验证安全适配器实例对象</h3>
	 *
	 * @param algorithm <span class="en-US">Signature algorithm name</span>
	 *                  <span class="zh-CN">签名算法名称</span>
	 * @param publicKey <span class="en-US">Public Key instance</span>
	 *                  <span class="zh-CN">公钥证书实例对象</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter RSAVerifier(final String algorithm, final PublicKey publicKey) throws CryptoException {
		return new RSACryptoAdapterImpl(
				new CipherConfig(algorithm, Globals.DEFAULT_VALUE_STRING, Globals.DEFAULT_VALUE_STRING),
				CryptoMode.VERIFY, new BaseCryptoAdapter.CipherKey(publicKey));
	}

	/**
	 * <h3 class="en-US">Generate RSA KeyPair</h3>
	 * <h3 class="zh-CN">生成RSA密钥对</h3>
	 *
	 * @return <span class="en-US">Generated keypair</span>
	 * <span class="zh-CN">生成的密钥对</span>
	 */
	public static KeyPair RSAKeyPair() {
		return RSAKeyPair(1024, "SHA1PRNG");
	}

	/**
	 * <h3 class="en-US">Generate RSA KeyPair</h3>
	 * <h3 class="zh-CN">生成RSA密钥对</h3>
	 *
	 * @param keySize <span class="en-US">Key size</span>
	 *                <span class="zh-CN">密钥长度</span>
	 * @return <span class="en-US">Generated keypair</span>
	 * <span class="zh-CN">生成的密钥对</span>
	 */
	public static KeyPair RSAKeyPair(final int keySize) {
		return RSAKeyPair(keySize, "SHA1PRNG");
	}

	/**
	 * <h3 class="en-US">Generate RSA KeyPair</h3>
	 * <h3 class="zh-CN">生成RSA密钥对</h3>
	 *
	 * @param keySize         <span class="en-US">Key size</span>
	 *                        <span class="zh-CN">密钥长度</span>
	 * @param randomAlgorithm <span class="en-US">Random algorithm</span>
	 *                        <span class="zh-CN">随机数算法</span>
	 * @return <span class="en-US">Generated keypair</span>
	 * <span class="zh-CN">生成的密钥对</span>
	 */
	public static KeyPair RSAKeyPair(final int keySize, final String randomAlgorithm) {
		return CertificateUtils.keyPair("RSA", randomAlgorithm, Globals.DEFAULT_VALUE_STRING, keySize);
	}

	/**
	 * <h3 class="en-US">Initialize SM2 encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化SM2加密安全适配器实例对象</h3>
	 *
	 * @param publicKey <span class="en-US">Public Key instance</span>
	 *                  <span class="zh-CN">公钥证书实例对象</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SM2Encryptor(final PublicKey publicKey) throws CryptoException {
		return new SM2CryptoAdapterImpl(
				new CipherConfig("SM2", Globals.DEFAULT_VALUE_STRING, Globals.DEFAULT_VALUE_STRING),
				CryptoMode.ENCRYPT, new BaseCryptoAdapter.CipherKey(publicKey));
	}

	/**
	 * <h3 class="en-US">Initialize SM2 decryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化SM2解密安全适配器实例对象</h3>
	 *
	 * @param privateKey <span class="en-US">Private Key instance</span>
	 *                   <span class="zh-CN">私钥证书实例对象</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SM2Decryptor(final PrivateKey privateKey) throws CryptoException {
		return new SM2CryptoAdapterImpl(
				new CipherConfig("SM2", Globals.DEFAULT_VALUE_STRING, Globals.DEFAULT_VALUE_STRING),
				CryptoMode.DECRYPT, new BaseCryptoAdapter.CipherKey(privateKey));
	}

	/**
	 * <h3 class="en-US">Initialize SM2 signer secure provider</h3>
	 * <h3 class="zh-CN">初始化SM2签名安全适配器实例对象</h3>
	 *
	 * @param privateKey <span class="en-US">Private Key instance</span>
	 *                   <span class="zh-CN">私钥证书实例对象</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SM2Signer(final PrivateKey privateKey) throws CryptoException {
		return new SM2CryptoAdapterImpl(
				new CipherConfig("SM3withSM2", Globals.DEFAULT_VALUE_STRING, Globals.DEFAULT_VALUE_STRING),
				CryptoMode.SIGNATURE, new BaseCryptoAdapter.CipherKey(privateKey));
	}

	/**
	 * <h3 class="en-US">Initialize SM2 signature verifier secure provider</h3>
	 * <h3 class="zh-CN">初始化SM2签名验证安全适配器实例对象</h3>
	 *
	 * @param publicKey <span class="en-US">Public Key instance</span>
	 *                  <span class="zh-CN">公钥证书实例对象</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter SM2Verifier(final PublicKey publicKey) throws CryptoException {
		return new SM2CryptoAdapterImpl(
				new CipherConfig("SM3withSM2", Globals.DEFAULT_VALUE_STRING, Globals.DEFAULT_VALUE_STRING),
				CryptoMode.VERIFY, new BaseCryptoAdapter.CipherKey(publicKey));
	}

	/**
	 * <h3 class="en-US">Generate SM2 KeyPair</h3>
	 * <h3 class="zh-CN">生成SM2密钥对</h3>
	 *
	 * @return <span class="en-US">Generated keypair</span>
	 * <span class="zh-CN">生成的密钥对</span>
	 */
	public static KeyPair SM2KeyPair() {
		return SM2KeyPair("SHA1PRNG");
	}

	/**
	 * <h3 class="en-US">Generate SM2 KeyPair</h3>
	 * <h3 class="zh-CN">生成SM2密钥对</h3>
	 *
	 * @param randomAlgorithm <span class="en-US">Random algorithm</span>
	 *                        <span class="zh-CN">随机数算法</span>
	 * @return <span class="en-US">Generated keypair</span>
	 * <span class="zh-CN">生成的密钥对</span>
	 */
	public static KeyPair SM2KeyPair(final String randomAlgorithm) {
		return CertificateUtils.keyPair("EC", randomAlgorithm, "sm2p256v1", Globals.INITIALIZE_INT_VALUE);
	}

	/**
	 * <h3 class="en-US">Convert data bytes from C1|C2|C3 to C1|C3|C2</h3>
	 * <h3 class="zh-CN">转换字节数组从C1|C2|C3到C1|C3|C2</h3>
	 *
	 * @param dataBytes <span class="en-US">C1|C2|C3 data bytes</span>
	 *                  <span class="zh-CN">C1|C2|C3格式字节数组</span>
	 * @return <span class="en-US">C1|C3|C2 data bytes</span>
	 * <span class="zh-CN">C1|C3|C2格式字节数组</span>
	 */
	public static byte[] C1C2C3toC1C3C2(final byte[] dataBytes) {
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(dataBytes.length);
		byteArrayOutputStream.write(dataBytes, 0, 65);
		byteArrayOutputStream.write(dataBytes, 97, dataBytes.length - 97);
		byteArrayOutputStream.write(dataBytes, 65, 32);
		return byteArrayOutputStream.toByteArray();
	}

	/**
	 * <h3 class="en-US">Convert data bytes from C1|C3|C2 to C1|C2|C3</h3>
	 * <h3 class="zh-CN">转换字节数组从C1|C2|C3到C1|C3|C2</h3>
	 *
	 * @param dataBytes <span class="en-US">C1|C3|C2 data bytes</span>
	 *                  <span class="zh-CN">C1|C3|C2格式字节数组</span>
	 * @return <span class="en-US">C1|C2|C3 data bytes</span>
	 * <span class="zh-CN">C1|C2|C3格式字节数组</span>
	 */
	public static byte[] C1C3C2toC1C2C3(final byte[] dataBytes) {
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(dataBytes.length);
		byteArrayOutputStream.write(dataBytes, 0, 65);
		byteArrayOutputStream.write(dataBytes, dataBytes.length - 32, 32);
		byteArrayOutputStream.write(dataBytes, 65, dataBytes.length - 97);
		return byteArrayOutputStream.toByteArray();
	}

	/**
	 * <h3 class="en-US">Initialize AES encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化AES加密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter AESEncryptor(final byte[] keyBytes) throws CryptoException {
		return AESEncryptor("CBC", "PKCS5Padding", keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize AES encryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化AES加密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8", "CFB128", "OFB128"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter AESEncryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return new AESCryptoAdapterImpl(new CipherConfig("AES", mode, padding), CryptoMode.ENCRYPT, keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize AES decryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化AES解密安全适配器实例对象</h3>
	 *
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter AESDecryptor(final byte[] keyBytes) throws CryptoException {
		return AESDecryptor("CBC", "PKCS5Padding", keyBytes);
	}

	/**
	 * <h3 class="en-US">Initialize AES decryptor secure provider</h3>
	 * <h3 class="zh-CN">初始化AES解密安全适配器实例对象</h3>
	 * <span>
	 * mode: "ECB", "CBC", "CTR", "CTS", "CFB", "OFB", "CFB8", "OFB8", "CFB128", "OFB128"
	 * padding: "PKCS5Padding", "PKCS7Padding", "ISO10126Padding", "X9.23Padding"
	 * </span>
	 *
	 * @param mode     <span class="en-US">Cipher Mode</span>
	 *                 <span class="zh-CN">分组密码模式</span>
	 * @param padding  <span class="en-US">Padding Mode</span>
	 *                 <span class="zh-CN">数据填充模式</span>
	 * @param keyBytes <span class="en-US">key bytes</span>
	 *                 <span class="zh-CN">密钥字节数组</span>
	 * @return <span class="en-US">Initialized secure provider instance</span>
	 * <span class="zh-CN">初始化的安全适配器实例对象</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static SecureAdapter AESDecryptor(final String mode, final String padding, final byte[] keyBytes)
			throws CryptoException {
		return new AESCryptoAdapterImpl(new CipherConfig("AES", mode, padding), CryptoMode.DECRYPT, keyBytes);
	}
	/*
	 * Key generators
	 */

	/**
	 * <h3 class="en-US">Generate AES128 key bytes</h3>
	 * <h3 class="zh-CN">生成AES128密钥字节数组</h3>
	 *
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 */
	public static byte[] AES128Key() {
		return AES128Key("SHA1PRNG");
	}

	/**
	 * <h3 class="en-US">Generate AES128 key bytes</h3>
	 * <h3 class="zh-CN">生成AES128密钥字节数组</h3>
	 *
	 * @param randomAlgorithm <span class="en-US">Random algorithm</span>
	 *                        <span class="zh-CN">随机数算法</span>
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 */
	public static byte[] AES128Key(final String randomAlgorithm) {
		try {
			return symmetricKey("AES", 128, randomAlgorithm);
		} catch (CryptoException e) {
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Generate AES192 key bytes</h3>
	 * <h3 class="zh-CN">生成AES192密钥字节数组</h3>
	 *
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 */
	public static byte[] AES192Key() {
		return AES192Key("SHA1PRNG");
	}

	/**
	 * <h3 class="en-US">Generate AES192 key bytes</h3>
	 * <h3 class="zh-CN">生成AES192密钥字节数组</h3>
	 *
	 * @param randomAlgorithm <span class="en-US">Random algorithm</span>
	 *                        <span class="zh-CN">随机数算法</span>
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 */
	public static byte[] AES192Key(final String randomAlgorithm) {
		try {
			return symmetricKey("AES", 192, randomAlgorithm);
		} catch (CryptoException e) {
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Generate AES256 key bytes</h3>
	 * <h3 class="zh-CN">生成AES256密钥字节数组</h3>
	 *
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 */
	public static byte[] AES256Key() {
		return AES256Key("SHA1PRNG");
	}

	/**
	 * <h3 class="en-US">Generate AES256 key bytes</h3>
	 * <h3 class="zh-CN">生成AES256密钥字节数组</h3>
	 *
	 * @param randomAlgorithm <span class="en-US">Random algorithm</span>
	 *                        <span class="zh-CN">随机数算法</span>
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 */
	public static byte[] AES256Key(final String randomAlgorithm) {
		try {
			return symmetricKey("AES", 256, randomAlgorithm);
		} catch (CryptoException e) {
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Retrieve RSA Key Size</h3>
	 * <h3 class="zh-CN">读取RSA密钥长度</h3>
	 *
	 * @param key <span class="en-US">RSA key instance</span>
	 *            <span class="zh-CN">RSA密钥实例对象</span>
	 * @return <span class="en-US">Retrieve key size</span>
	 * <span class="zh-CN">读取的密钥长度</span>
	 */
	public static int rsaKeySize(final Key key) {
		if (key == null) {
			return Globals.DEFAULT_VALUE_INT;
		}
		try {
			if (key instanceof PrivateKey) {
				return KeyFactory.getInstance("RSA").getKeySpec(key, RSAPrivateKeySpec.class).getModulus().toString(2).length();
			} else if (key instanceof RSAPublicKey) {
				return KeyFactory.getInstance("RSA").getKeySpec(key, RSAPublicKeySpec.class).getModulus().toString(2).length();
			}
			return Globals.DEFAULT_VALUE_INT;
		} catch (NoSuchAlgorithmException | InvalidKeySpecException ignored) {
			return Globals.DEFAULT_VALUE_INT;
		}
	}

	/**
	 * <h3 class="en-US">Generate symmetric key bytes</h3>
	 * <h3 class="zh-CN">生成对称加密密钥字节数组</h3>
	 *
	 * @param algorithm       <span class="en-US">Algorithm name</span>
	 *                        <span class="zh-CN">算法名称</span>
	 * @param keySize         <span class="en-US">Key size</span>
	 *                        <span class="zh-CN">密钥长度</span>
	 * @param randomAlgorithm <span class="en-US">Random algorithm</span>
	 *                        <span class="zh-CN">随机数算法</span>
	 * @return <span class="en-US">Generated key bytes or zero length byte array if process error</span>
	 * <span class="zh-CN">生成的密钥字节数组，如果出现异常则返回长度为0的字节数组</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	public static byte[] symmetricKey(final String algorithm, final int keySize, final String randomAlgorithm)
			throws CryptoException {
		if (StringUtils.isEmpty(algorithm)) {
			throw new CryptoException(0x00000015000DL, "Unknown_Algorithm_Digits_Error", algorithm);
		}

		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm, "BC");
			switch (algorithm.toUpperCase()) {
				case "AES":
				case "RC4":
					keyGenerator.init(keySize, SecureRandom.getInstance(randomAlgorithm));
					break;
				case "SM4":
				case "RC2":
				case "RC5":
				case "RC6":
					keyGenerator.init(keySize, new SecureRandom());
					break;
				case "DES":
				case "DESEDE":
				case "BLOWFISH":
					break;
				default:
					throw new CryptoException(0x00000015000DL, "Unknown_Algorithm_Digits_Error", algorithm);
			}
			SecretKey secretKey = keyGenerator.generateKey();
			return secretKey.getEncoded();
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new CryptoException(0x000000150009L, "Init_Key_Crypto_Error", e);
		}
	}

	/**
	 * <h3 class="en-US">Calculate digest result of given object using given secure adapter</h3>
	 * <h3 class="zh-CN">使用给定的安全适配器计算给定数据的计算结果</h3>
	 *
	 * @param source        <span class="en-US">source object</span>
	 *                      <span class="zh-CN">原始数据对象</span>
	 * @param secureAdapter <span class="en-US">Secure provider instance</span>
	 *                      <span class="zh-CN">安全适配器实例对象</span>
	 * @return <span class="en-US">Calculate result or zero-length arrays if processes have error</span>
	 * <span class="zh-CN">计算结果，如果出现错误则返回长度为0的字节数组</span>
	 * @throws CryptoException <span class="en-US">If algorithm didn't find</span>
	 *                         <span class="zh-CN">如果算法未找到</span>
	 */
	private static byte[] calculate(final Object source, final SecureAdapter secureAdapter) throws CryptoException {
		if (source instanceof File) {
			try (InputStream inputStream = new FileInputStream((File) source)) {
				byte[] readBuffer = new byte[Globals.READ_FILE_BUFFER_SIZE];
				int readLength;
				while ((readLength = inputStream.read(readBuffer)) > 0) {
					secureAdapter.append(readBuffer, 0, readLength);
				}
			} catch (Exception e) {
				LOGGER.error("Calculate_Digits_Security_Error", e);
				return new byte[0];
			}
			return secureAdapter.finish();
		} else if (source instanceof SmbFile) {
			try (InputStream inputStream = new SmbFileInputStream((SmbFile) source)) {
				byte[] readBuffer = new byte[Globals.READ_FILE_BUFFER_SIZE];
				int readLength;
				while ((readLength = inputStream.read(readBuffer)) > 0) {
					secureAdapter.append(readBuffer, 0, readLength);
				}
			} catch (Exception e) {
				LOGGER.error("Calculate_Digits_Security_Error", e);
				return new byte[0];
			}
			return secureAdapter.finish();
		} else {
			return secureAdapter.finish(ConvertUtils.toByteArray(source));
		}
	}
}
