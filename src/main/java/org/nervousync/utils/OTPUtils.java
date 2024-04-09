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

import org.nervousync.commons.Globals;
import org.nervousync.exceptions.utils.DataInvalidException;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * <h2 class="en-US">OTP(One-time Password Algorithm) Utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Calculate OTP fixed time value</ul>
 *     <ul>Generate random key</ul>
 *     <ul>Generate TOTP/HOTP Code</ul>
 *     <ul>Verify TOTP/HOTP Code</ul>
 * </span>
 * <h2 class="zh-CN">一次性密码算法工具集</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>计算一次性密码算法的修正时间值</ul>
 *     <ul>生成随机密钥</ul>
 *     <ul>生成基于HMAC算法加密的一次性密码/基于时间戳算法的一次性密码值</ul>
 *     <ul>验证基于HMAC算法加密的一次性密码/基于时间戳算法的一次性密码值</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.2 $ $Date: Jun 04, 2019 10:47:28 $
 */
public final class OTPUtils {
	/**
	 * <span class="en-US">Multilingual supported logger instance</span>
	 * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(OTPUtils.class);

	//  Unit: Second
	/**
	 * <span class="en-US">Time Step, Unit: Second</span>
	 * <span class="zh-CN">时间步长，单位：秒</span>
	 */
	private static final int DEFAULT_SYNC_COUNT = 30;

	//  Default 3, Maximum 17 (From Google Docs)
	/**
	 * <span class="en-US">Default window size</span>
	 * <span class="zh-CN">默认的最多可偏移时间</span>
	 */
	private static final int DEFAULT_WINDOW_SIZE = 3;
	/**
	 * <span class="en-US">Default secret size</span>
	 * <span class="zh-CN">默认的密钥长度</span>
	 */
	private static final int DEFAULT_SECRET_SIZE = 10;
	/**
	 * <span class="en-US">Default secret seed character</span>
	 * <span class="zh-CN">默认的密钥种子字符</span>
	 */
	private static final String DEFAULT_SECRET_SEED = "TmVydm91c3luY0RlZmF1bHRTZWNyZXRTZWVk";
	/**
	 * <span class="en-US">Default random algorithm</span>
	 * <span class="zh-CN">默认的随机数算法</span>
	 */
	private static final String DEFAULT_RANDOM_ALGORITHM = "SHA1PRNG";

	/**
	 * <h3 class="en-US">Private constructor for OTPUtils</h3>
	 * <h3 class="zh-CN">一次性密码算法工具集的私有构造方法</h3>
	 */
	private OTPUtils() {
	}

	/**
	 * <h3 class="en-US">Calculate fixed time</h3>
	 * <h3 class="zh-CN">计算修正时间</h3>
	 *
	 * @param secret   <span class="en-US">Secret key string</span>
	 *                 <span class="zh-CN">随机密钥字符串</span>
	 * @param authCode <span class="en-US">Client generated authenticate code</span>
	 *                 <span class="zh-CN">客户端生成的随机验证码</span>
	 * @return <span class="en-US">Calculated fixed time</span>
	 * <span class="zh-CN">计算出的修正时间</span>
	 */
	public static long calculateFixedTime(final String secret, final int authCode) {
		return calculateFixedTime(CalcType.HmacSHA1, secret, authCode, Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * <h3 class="en-US">Calculate fixed time</h3>
	 * <h3 class="zh-CN">计算修正时间</h3>
	 *
	 * @param secret    <span class="en-US">Secret key string</span>
	 *                  <span class="zh-CN">随机密钥字符串</span>
	 * @param authCode  <span class="en-US">Client generated authenticate code</span>
	 *                  <span class="zh-CN">客户端生成的随机验证码</span>
	 * @param syncCount <span class="en-US">Time Step, Unit: Second</span>
	 *                  <span class="zh-CN">时间步长，单位：秒</span>
	 * @return <span class="en-US">Calculated fixed time</span>
	 * <span class="zh-CN">计算出的修正时间</span>
	 */
	public static long calculateFixedTime(final String secret, final int authCode, final int syncCount) {
		return calculateFixedTime(CalcType.HmacSHA1, secret, authCode, syncCount);
	}

	/**
	 * <h3 class="en-US">Calculate fixed time</h3>
	 * <h3 class="zh-CN">计算修正时间</h3>
	 *
	 * @param calcType <span class="en-US">Calculate type</span>
	 *                 <span class="zh-CN">密码算法类型</span>
	 * @param secret   <span class="en-US">Secret key string</span>
	 *                 <span class="zh-CN">随机密钥字符串</span>
	 * @param authCode <span class="en-US">Client generated authenticate code</span>
	 *                 <span class="zh-CN">客户端生成的随机验证码</span>
	 * @return <span class="en-US">Calculated fixed time</span>
	 * <span class="zh-CN">计算出的修正时间</span>
	 */
	public static long calculateFixedTime(final CalcType calcType, final String secret, final int authCode) {
		return calculateFixedTime(calcType, secret, authCode, Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * <h3 class="en-US">Calculate fixed time</h3>
	 * <h3 class="zh-CN">计算修正时间</h3>
	 *
	 * @param calcType  <span class="en-US">Calculate type</span>
	 *                  <span class="zh-CN">密码算法类型</span>
	 * @param secret    <span class="en-US">Secret key string</span>
	 *                  <span class="zh-CN">随机密钥字符串</span>
	 * @param authCode  <span class="en-US">Client generated authenticate code</span>
	 *                  <span class="zh-CN">客户端生成的随机验证码</span>
	 * @param syncCount <span class="en-US">Time Step, Unit: Second</span>
	 *                  <span class="zh-CN">时间步长，单位：秒</span>
	 * @return <span class="en-US">Calculated fixed time</span>
	 * <span class="zh-CN">计算出的修正时间</span>
	 */
	public static long calculateFixedTime(final CalcType calcType, final String secret,
	                                      final int authCode, final int syncCount) {
		for (int i = -12; i <= 12; i++) {
			long fixedTime = i * 60 * 60 * 1000L;
			if (validateTOTPCode(authCode, calcType, secret, fixedTime, syncCount, Globals.INITIALIZE_INT_VALUE)) {
				return fixedTime;
			}
		}
		return Globals.DEFAULT_VALUE_INT;
	}

	/**
	 * <h3 class="en-US">Generate TOTP(Time-based One-time Password) code</h3>
	 * <h3 class="zh-CN">生成基于时间的一次性密码</h3>
	 *
	 * @param secret <span class="en-US">Secret key string</span>
	 *               <span class="zh-CN">随机密钥字符串</span>
	 * @return <span class="en-US">Generated code</span>
	 * <span class="zh-CN">生成的一次性密码</span>
	 */
	public static String generateTOTPCode(final String secret) {
		return generateTOTPCode(CalcType.HmacSHA1, secret, Globals.INITIALIZE_INT_VALUE, Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * <h3 class="en-US">Generate TOTP(Time-based One-time Password) code</h3>
	 * <h3 class="zh-CN">生成基于时间的一次性密码</h3>
	 *
	 * @param secret    <span class="en-US">Secret key string</span>
	 *                  <span class="zh-CN">随机密钥字符串</span>
	 * @param fixedTime <span class="en-US">Client fixed time</span>
	 *                  <span class="zh-CN">客户端的修正时间</span>
	 * @return <span class="en-US">Generated code</span>
	 * <span class="zh-CN">生成的一次性密码</span>
	 */
	public static String generateTOTPCode(final String secret, final long fixedTime) {
		return generateTOTPCode(CalcType.HmacSHA1, secret, fixedTime, Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * <h3 class="en-US">Generate TOTP(Time-based One-time Password) code</h3>
	 * <h3 class="zh-CN">生成基于时间的一次性密码</h3>
	 *
	 * @param secret    <span class="en-US">Secret key string</span>
	 *                  <span class="zh-CN">随机密钥字符串</span>
	 * @param fixedTime <span class="en-US">Client fixed time</span>
	 *                  <span class="zh-CN">客户端的修正时间</span>
	 * @param syncCount <span class="en-US">Time Step, Unit: Second</span>
	 *                  <span class="zh-CN">时间步长，单位：秒</span>
	 * @return <span class="en-US">Generated code</span>
	 * <span class="zh-CN">生成的一次性密码</span>
	 */
	public static String generateTOTPCode(final String secret, final long fixedTime, final int syncCount) {
		return generateTOTPCode(CalcType.HmacSHA1, secret, fixedTime, syncCount);
	}

	/**
	 * <h3 class="en-US">Generate TOTP(Time-based One-time Password) code</h3>
	 * <h3 class="zh-CN">生成基于时间的一次性密码</h3>
	 *
	 * @param calcType  <span class="en-US">Calculate type</span>
	 *                  <span class="zh-CN">密码算法类型</span>
	 * @param secret    <span class="en-US">Secret key string</span>
	 *                  <span class="zh-CN">随机密钥字符串</span>
	 * @param fixedTime <span class="en-US">Client fixed time</span>
	 *                  <span class="zh-CN">客户端的修正时间</span>
	 * @return <span class="en-US">Generated code</span>
	 * <span class="zh-CN">生成的一次性密码</span>
	 */
	public static String generateTOTPCode(final CalcType calcType, final String secret, final long fixedTime) {
		return generateTOTPCode(calcType, secret, fixedTime, Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * <h3 class="en-US">Generate TOTP(Time-based One-time Password) code</h3>
	 * <h3 class="zh-CN">生成基于时间的一次性密码</h3>
	 *
	 * @param calcType  <span class="en-US">Calculate type</span>
	 *                  <span class="zh-CN">密码算法类型</span>
	 * @param secret    <span class="en-US">Secret key string</span>
	 *                  <span class="zh-CN">随机密钥字符串</span>
	 * @param fixedTime <span class="en-US">Client fixed time</span>
	 *                  <span class="zh-CN">客户端的修正时间</span>
	 * @param syncCount <span class="en-US">Time Step, Unit: Second</span>
	 *                  <span class="zh-CN">时间步长，单位：秒</span>
	 * @return <span class="en-US">Generated code</span>
	 * <span class="zh-CN">生成的一次性密码</span>
	 */
	public static String generateTOTPCode(final CalcType calcType, final String secret,
	                                      final long fixedTime, final int syncCount) {
		int authCode = OTPUtils.generateTOTPCode(calcType, secret,
				fixedTime, syncCount, Globals.INITIALIZE_INT_VALUE);
		if (authCode == Globals.DEFAULT_VALUE_INT) {
			return Globals.DEFAULT_VALUE_STRING;
		}

		StringBuilder returnCode = new StringBuilder(Integer.toString(authCode));
		while (returnCode.length() < 6) {
			returnCode.insert(0, "0");
		}
		return returnCode.toString();
	}

	/**
	 * <h3 class="en-US">Validate TOTP(Time-based One-time Password) code</h3>
	 * <h3 class="zh-CN">验证基于时间的一次性密码</h3>
	 *
	 * @param authCode  <span class="en-US">Authenticate code</span>
	 *                  <span class="zh-CN">需要验证的一次性密码</span>
	 * @param secret    <span class="en-US">Secret key string</span>
	 *                  <span class="zh-CN">随机密钥字符串</span>
	 * @param fixedTime <span class="en-US">Client fixed time</span>
	 *                  <span class="zh-CN">客户端的修正时间</span>
	 * @return <span class="en-US">Validate result</span>
	 * <span class="zh-CN">验证结果</span>
	 */
	public static boolean validateTOTPCode(final int authCode, final String secret, final long fixedTime) {
		return validateTOTPCode(authCode, CalcType.HmacSHA1, secret, fixedTime,
				Globals.DEFAULT_VALUE_INT, Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * <h3 class="en-US">Validate TOTP(Time-based One-time Password) code</h3>
	 * <h3 class="zh-CN">验证基于时间的一次性密码</h3>
	 *
	 * @param authCode  <span class="en-US">Authenticate code</span>
	 *                  <span class="zh-CN">需要验证的一次性密码</span>
	 * @param secret    <span class="en-US">Secret key string</span>
	 *                  <span class="zh-CN">随机密钥字符串</span>
	 * @param fixedTime <span class="en-US">Client fixed time</span>
	 *                  <span class="zh-CN">客户端的修正时间</span>
	 * @param fixWindow <span class="en-US">Fix window size</span>
	 *                  <span class="zh-CN">最多可偏移时间</span>
	 * @return <span class="en-US">Validate result</span>
	 * <span class="zh-CN">验证结果</span>
	 */
	public static boolean validateTOTPCode(final int authCode, final String secret,
	                                       final long fixedTime, final int fixWindow) {
		return validateTOTPCode(authCode, CalcType.HmacSHA1, secret, fixedTime,
				Globals.DEFAULT_VALUE_INT, fixWindow);
	}

	/**
	 * <h3 class="en-US">Validate TOTP(Time-based One-time Password) code</h3>
	 * <h3 class="zh-CN">验证基于时间的一次性密码</h3>
	 *
	 * @param calcType  <span class="en-US">Calculate type</span>
	 *                  <span class="zh-CN">密码算法类型</span>
	 * @param authCode  <span class="en-US">Authenticate code</span>
	 *                  <span class="zh-CN">需要验证的一次性密码</span>
	 * @param secret    <span class="en-US">Secret key string</span>
	 *                  <span class="zh-CN">随机密钥字符串</span>
	 * @param fixedTime <span class="en-US">Client fixed time</span>
	 *                  <span class="zh-CN">客户端的修正时间</span>
	 * @param fixWindow <span class="en-US">Fix window size</span>
	 *                  <span class="zh-CN">最多可偏移时间</span>
	 * @return <span class="en-US">Validate result</span>
	 * <span class="zh-CN">验证结果</span>
	 */
	public static boolean validateTOTPCode(final int authCode, final CalcType calcType, final String secret,
	                                       final long fixedTime, final int syncCount, final int fixWindow) {
		if (authCode > Globals.INITIALIZE_INT_VALUE) {
			int minWindow = fixWindow < 0 ? (-1 * DEFAULT_WINDOW_SIZE) : (-1 * fixWindow);
			int maxWindow = fixWindow < 0 ? DEFAULT_WINDOW_SIZE : fixWindow;
			for (int i = minWindow; i <= maxWindow; i++) {
				int generateCode = generateTOTPCode(calcType, secret, fixedTime, syncCount, i);
				if (generateCode == authCode) {
					return true;
				}
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Generate HOTP(HMAC-based One-time Password) code</h3>
	 * <h3 class="zh-CN">生成基于HMAC算法加密的一次性密码</h3>
	 *
	 * @param secret     <span class="en-US">Secret key string</span>
	 *                   <span class="zh-CN">随机密钥字符串</span>
	 * @param randomCode <span class="en-US">Random number</span>
	 *                   <span class="zh-CN">随机数</span>
	 * @return <span class="en-US">Generated code</span>
	 * <span class="zh-CN">生成的一次性密码</span>
	 */
	public static int generateHOTPCode(final String secret, final long randomCode) {
		return generateCode(CalcType.HmacSHA1, secret, randomCode);
	}

	/**
	 * <h3 class="en-US">Generate HOTP(HMAC-based One-time Password) code</h3>
	 * <h3 class="zh-CN">生成基于HMAC算法加密的一次性密码</h3>
	 *
	 * @param calcType   <span class="en-US">Calculate type</span>
	 *                   <span class="zh-CN">密码算法类型</span>
	 * @param secret     <span class="en-US">Secret key string</span>
	 *                   <span class="zh-CN">随机密钥字符串</span>
	 * @param randomCode <span class="en-US">Random number</span>
	 *                   <span class="zh-CN">随机数</span>
	 * @return <span class="en-US">Generated code</span>
	 * <span class="zh-CN">生成的一次性密码</span>
	 */
	public static int generateHOTPCode(final CalcType calcType, final String secret, final long randomCode) {
		return generateCode(calcType, secret, randomCode);
	}

	/**
	 * <h3 class="en-US">Validate HOTP(HMAC-based One-time Password) code</h3>
	 * <h3 class="zh-CN">验证基于HMAC算法加密的一次性密码</h3>
	 *
	 * @param authCode   <span class="en-US">Authenticate code</span>
	 *                   <span class="zh-CN">需要验证的一次性密码</span>
	 * @param secret     <span class="en-US">Secret key string</span>
	 *                   <span class="zh-CN">随机密钥字符串</span>
	 * @param randomCode <span class="en-US">Random number</span>
	 *                   <span class="zh-CN">随机数</span>
	 * @return <span class="en-US">Validate result</span>
	 * <span class="zh-CN">验证结果</span>
	 */
	public static boolean validateHOTPCode(final int authCode, final String secret, final long randomCode) {
		return authCode > Globals.INITIALIZE_INT_VALUE
				? authCode == generateHOTPCode(CalcType.HmacSHA1, secret, randomCode)
				: Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Validate HOTP(HMAC-based One-time Password) code</h3>
	 * <h3 class="zh-CN">验证基于HMAC算法加密的一次性密码</h3>
	 *
	 * @param authCode   <span class="en-US">Authenticate code</span>
	 *                   <span class="zh-CN">需要验证的一次性密码</span>
	 * @param calcType   <span class="en-US">Calculate type</span>
	 *                   <span class="zh-CN">密码算法类型</span>
	 * @param secret     <span class="en-US">Secret key string</span>
	 *                   <span class="zh-CN">随机密钥字符串</span>
	 * @param randomCode <span class="en-US">Random number</span>
	 *                   <span class="zh-CN">随机数</span>
	 * @return <span class="en-US">Validate result</span>
	 * <span class="zh-CN">验证结果</span>
	 */
	public static boolean validateHOTPCode(final int authCode, final CalcType calcType, final String secret,
	                                       final long randomCode) {
		return authCode > Globals.INITIALIZE_INT_VALUE
				? authCode == generateHOTPCode(calcType, secret, randomCode)
				: Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Generate random secret key string</h3>
	 * <h3 class="zh-CN">生成随机的密码字符串</h3>
	 *
	 * @return <span class="en-US">Generated secret key string</span>
	 * <span class="zh-CN">生成的密码字符串</span>
	 */
	public static String generateRandomKey() {
		return generateRandomKey(DEFAULT_RANDOM_ALGORITHM, DEFAULT_SECRET_SEED, Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * <h3 class="en-US">Generate random secret key string</h3>
	 * <h3 class="zh-CN">生成随机的密码字符串</h3>
	 *
	 * @param size <span class="en-US">Secret size</span>
	 *             <span class="zh-CN">密钥长度</span>
	 * @return <span class="en-US">Generated secret key string</span>
	 * <span class="zh-CN">生成的密码字符串</span>
	 */
	public static String generateRandomKey(final int size) {
		return generateRandomKey(DEFAULT_RANDOM_ALGORITHM, DEFAULT_SECRET_SEED, size);
	}

	/**
	 * <h3 class="en-US">Generate random secret key string</h3>
	 * <h3 class="zh-CN">生成随机的密码字符串</h3>
	 *
	 * @param algorithm <span class="en-US">Secure random algorithm</span>
	 *                  <span class="zh-CN">安全随机数算法</span>
	 * @param seed      <span class="en-US">Secret seed character</span>
	 *                  <span class="zh-CN">密钥种子字符</span>
	 * @param size      <span class="en-US">Secret size</span>
	 *                  <span class="zh-CN">密钥长度</span>
	 * @return <span class="en-US">Generated secret key string</span>
	 * <span class="zh-CN">生成的密码字符串</span>
	 */
	public static String generateRandomKey(final String algorithm, final String seed, final int size) {
		String randomKey = null;
		try {
			SecureRandom secureRandom = StringUtils.notBlank(algorithm)
					? SecureRandom.getInstance(algorithm)
					: SecureRandom.getInstance(DEFAULT_RANDOM_ALGORITHM);
			if (StringUtils.notBlank(seed)) {
				secureRandom.setSeed(StringUtils.base64Decode(seed));
			}
			byte[] randomKeyBytes =
					secureRandom.generateSeed(size == Globals.DEFAULT_VALUE_INT ? DEFAULT_SECRET_SIZE : size);
			randomKey = StringUtils.base32Encode(randomKeyBytes, Boolean.FALSE);
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error("Random_Key_Generate_OTP_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}
		return randomKey;
	}

	/**
	 * <h3 class="en-US">Generate TOTP(Time-based One-time Password) code</h3>
	 * <h3 class="zh-CN">生成基于时间的一次性密码</h3>
	 *
	 * @param calcType  <span class="en-US">Calculate type</span>
	 *                  <span class="zh-CN">密码算法类型</span>
	 * @param secret    <span class="en-US">Secret key string</span>
	 *                  <span class="zh-CN">随机密钥字符串</span>
	 * @param fixedTime <span class="en-US">Client fixed time</span>
	 *                  <span class="zh-CN">客户端的修正时间</span>
	 * @param syncCount <span class="en-US">Time Step, Unit: Second</span>
	 *                  <span class="zh-CN">时间步长，单位：秒</span>
	 * @param fixWindow <span class="en-US">Fix window size</span>
	 *                  <span class="zh-CN">最多可偏移时间</span>
	 * @return <span class="en-US">Generated code</span>
	 * <span class="zh-CN">生成的一次性密码</span>
	 */
	private static int generateTOTPCode(final CalcType calcType, final String secret, final long fixedTime,
	                                    final int syncCount, final int fixWindow) {
		long currentTime = DateTimeUtils.currentTimeMillis();
		long calcTime = (currentTime + fixedTime) / 1000L;
		if (syncCount > 0) {
			calcTime /= syncCount;
		} else {
			calcTime /= DEFAULT_SYNC_COUNT;
		}
		calcTime += fixWindow;
		return generateCode(calcType, secret, calcTime);
	}

	/**
	 * <h3 class="en-US">Generate OTP(One-time Password) code</h3>
	 * <h3 class="zh-CN">生成基于时间的一次性密码</h3>
	 *
	 * @param calcType   <span class="en-US">Calculate type</span>
	 *                   <span class="zh-CN">密码算法类型</span>
	 * @param secret     <span class="en-US">Secret key string</span>
	 *                   <span class="zh-CN">随机密钥字符串</span>
	 * @param randomCode <span class="en-US">Random number</span>
	 *                   <span class="zh-CN">随机数</span>
	 * @return <span class="en-US">Generated code</span>
	 * <span class="zh-CN">生成的一次性密码</span>
	 */
	private static int generateCode(final CalcType calcType, final String secret, long randomCode) {
		byte[] signData = new byte[8];
		try {
			RawUtils.writeLong(signData, randomCode);
		} catch (DataInvalidException e) {
			LOGGER.error("Process_Signature_Data_OTP_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Globals.DEFAULT_VALUE_INT;
		}
		byte[] secretBytes = StringUtils.base32Decode(secret);
		byte[] hash;
		switch (calcType) {
			case HmacSHA1:
				hash = SecurityUtils.HmacSHA1(secretBytes, signData);
				break;
			case HmacSHA256:
				hash = SecurityUtils.HmacSHA256(secretBytes, signData);
				break;
			case HmacSHA512:
				hash = SecurityUtils.HmacSHA512(secretBytes, signData);
				break;
			default:
				return Globals.DEFAULT_VALUE_INT;
		}
		int offset = hash[hash.length - 1] & 0xF;
		long resultCode = 0L;
		for (int i = 0; i < 4; ++i) {
			resultCode = (resultCode << 8) | (hash[offset + i] & 0xFF);
		}
		resultCode &= 0x7FFFFFFF;
		resultCode %= 1000000;
		return (int) resultCode;
	}

	/**
	 * <h2 class="en-US">Enumeration of Calculate type</h2>
	 * <h2 class="zh-CN">密码算法类型枚举</h2>
	 */
	public enum CalcType {
		HmacSHA1, HmacSHA256, HmacSHA512
	}
}
