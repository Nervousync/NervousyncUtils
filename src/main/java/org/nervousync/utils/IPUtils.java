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

import jakarta.annotation.Nonnull;
import org.nervousync.beans.ip.IPRange;
import org.nervousync.commons.Globals;
import org.nervousync.commons.RegexGlobals;
import org.nervousync.enumerations.ip.IPType;

import java.math.BigInteger;

/**
 * <h2 class="en-US">IP Address Utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Calculate IP range by given address and CIDR value</ul>
 *     <ul>Convert between netmask address and CIDR value</ul>
 *     <ul>Convert between IPv4 and IPv6</ul>
 *     <ul>Convert between IP address and BigInteger(for support IPv6)</ul>
 *     <ul>Expand the combo IPv6 address</ul>
 * </span>
 * <h2 class="zh-CN">IP地址工具</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>根据给定的地址和CIDR，计算IP地址范围</ul>
 *     <ul>在子网掩码和CIDR之间转换数据</ul>
 *     <ul>在IPv4和IPv6之间转换数据</ul>
 *     <ul>在IP地址和BigInteger之间转换数据</ul>
 *     <ul>将压缩显示的IPv6地址展开</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Aug 15, 2022 16:23:13 $
 */
public final class IPUtils {
	/**
	 * <span class="en-US">Split character for IPv4 address</span>
	 * <span class="zh-CN">IPv4地址的间隔符</span>
	 */
	private static final String SPLIT_CHARACTER_IPV4 = ".";
	/**
	 * <span class="en-US">Split character for IPv6 address</span>
	 * <span class="zh-CN">IPv6地址的间隔符</span>
	 */
	private static final String SPLIT_CHARACTER_IPV6 = ":";
	/**
	 * <span class="en-US">Split character for combo IPv6 address</span>
	 * <span class="zh-CN">IPv6压缩地址的间隔符</span>
	 */
	private static final String SPLIT_COMBO_CHARACTER_IPV6 = "::";

	/**
	 * <h3 class="en-US">Private constructor for IPUtils</h3>
	 * <h3 class="zh-CN">IP地址工具集的私有构造方法</h3>
	 */
	private IPUtils() {
	}

	/**
	 * <h3 class="en-US">Calculate IP range by given address and CIDR value</h3>
	 * <h3 class="zh-CN">根据给定的地址和CIDR，计算IP地址范围</h3>
	 *
	 * @param ipAddress <span class="en-US">IP address</span>
	 *                  <span class="zh-CN">IP地址</span>
	 * @param cidr      <span class="en-US">CIDR value</span>
	 *                  <span class="zh-CN">CIDR值</span>
	 * @return <span class="en-US">Calculate result of IPRange instance</span>
	 * <span class="zh-CN">根据计算结果生成的IPRange对象</span>
	 */
	public static IPRange calcRange(@Nonnull final String ipAddress, final int cidr) {
		IPRange ipRange = new IPRange();
		final String beginAddress;
		final String endAddress;
		if (ipAddress.contains(SPLIT_CHARACTER_IPV6)) {
			ipRange.setIpType(IPType.IPv6);
			beginAddress = beginIPv6(ipAddress, cidr);
			endAddress = endIPv6(beginAddress, cidr);
		} else {
			ipRange.setIpType(IPType.IPv4);
			String netmask = CIDRToNetmask(cidr);
			beginAddress = beginIPv4(ipAddress, netmask);
			endAddress = endIPv4(beginAddress, netmask);
		}

		ipRange.setBeginAddress(beginAddress);
		ipRange.setEndAddress(endAddress);

		return ipRange;
	}

	/**
	 * <h3 class="en-US">Convert netmask string to CIDR value</h3>
	 * <h3 class="zh-CN">转换子网掩码字符串为CIDR值</h3>
	 *
	 * @param netmask <span class="en-US">IP address</span>
	 *                <span class="zh-CN">IP地址</span>
	 * @return <span class="en-US">CIDR value</span>
	 * <span class="zh-CN">CIDR值</span>
	 */
	public static int NetmaskToCIDR(@Nonnull final String netmask) {
		int result = 0;
		String[] splitItems = StringUtils.tokenizeToStringArray(netmask, SPLIT_CHARACTER_IPV4);

		for (String splitItem : splitItems) {
			int number = Integer.parseInt(splitItem);
			while (number > 0) {
				if ((number % 2) == 1) {
					result++;
				}
				number /= 2;
			}
		}
		return result;
	}

	/**
	 * <h3 class="en-US">Convert CIDR value to netmask string</h3>
	 * <h3 class="zh-CN">转换CIDR值为子网掩码字符串</h3>
	 *
	 * @param cidr <span class="en-US">CIDR value</span>
	 *             <span class="zh-CN">CIDR值</span>
	 * @return <span class="en-US">Netmask address string</span>
	 * <span class="zh-CN">子网掩码字符串</span>
	 */
	public static String CIDRToNetmask(final int cidr) {
		int calcCIDR = cidr;
		if (calcCIDR >= 0 && calcCIDR <= 32) {
			StringBuilder stringBuilder = new StringBuilder();
			int index = 0;
			while (index < 4) {
				stringBuilder.append(SPLIT_CHARACTER_IPV4).append(fillBitsFromLeft(calcCIDR));
				calcCIDR -= 8;
				if (calcCIDR < 0) {
					calcCIDR = 0;
				}
				index++;
			}
			return stringBuilder.substring(1);
		}
		return Globals.DEFAULT_VALUE_STRING;
	}

	/**
	 * <h3 class="en-US">Check given IP address string is IPv4 address</h3>
	 * <h3 class="zh-CN">检查给定的IP地址字符串是合法的IPv4地址</h3>
	 *
	 * @param ipAddress <span class="en-US">IP address string</span>
	 *                  <span class="zh-CN">IP地址字符串</span>
	 * @return <span class="en-US">Check result. <code>true</code> for valid, <code>false</code> for invalid</span>
	 * <span class="zh-CN">检查结果。<code>true</code>合法地址，<code>false</code>非法地址</span>
	 */
	public static boolean isIPv4Address(@Nonnull final String ipAddress) {
		return StringUtils.matches(ipAddress, RegexGlobals.IPV4_REGEX);
	}

	/**
	 * <h3 class="en-US">Check given IP address string is IPv6 address</h3>
	 * <h3 class="zh-CN">检查给定的IP地址字符串是合法的IPv6地址</h3>
	 *
	 * @param ipAddress <span class="en-US">IP address string</span>
	 *                  <span class="zh-CN">IP地址字符串</span>
	 * @return <span class="en-US">Check result. <code>true</code> for valid, <code>false</code> for invalid</span>
	 * <span class="zh-CN">检查结果。<code>true</code>合法地址，<code>false</code>非法地址</span>
	 */
	public static boolean isIPv6Address(@Nonnull final String ipAddress) {
		return StringUtils.matches(ipAddress, RegexGlobals.IPV6_REGEX)
				|| StringUtils.matches(ipAddress, RegexGlobals.IPV6_COMPRESS_REGEX);
	}

	/**
	 * <h3 class="en-US">Convert given IPv4 address string to compatible IPv6 address</h3>
	 * <h3 class="zh-CN">转换给定的IPv4地址为IPv6兼容地址</h3>
	 *
	 * @param ipAddress <span class="en-US">IPv4 address string</span>
	 *                  <span class="zh-CN">IP地址字符串</span>
	 * @return <span class="en-US">Compatible IPv6 address string</span>
	 * <span class="zh-CN">转换后的IPv6兼容地址</span>
	 */
	public static String IPv4ToCompatibleIPv6(@Nonnull final String ipAddress) {
		if (StringUtils.matches(ipAddress, RegexGlobals.IPV4_REGEX)) {
			return SPLIT_COMBO_CHARACTER_IPV6 + ipAddress;
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Convert given IPv4 address string to IPv6 address</h3>
	 * <h3 class="zh-CN">转换给定的IPv4地址为IPv6兼容地址</h3>
	 *
	 * @param ipAddress <span class="en-US">IPv4 address string</span>
	 *                  <span class="zh-CN">IP地址字符串</span>
	 * @return <span class="en-US">IPv6 address string</span>
	 * <span class="zh-CN">转换后的IPv6地址</span>
	 */
	public static String IPv4ToIPv6(@Nonnull final String ipAddress) {
		return IPv4ToIPv6(ipAddress, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Convert given IPv4 address string to IPv6 address</h3>
	 * <h3 class="zh-CN">转换给定的IPv4地址为IPv6兼容地址</h3>
	 *
	 * @param ipAddress <span class="en-US">IPv4 address string</span>
	 *                  <span class="zh-CN">IP地址字符串</span>
	 * @param collapse  <span class="en-US">Collapse converted IPv6 address</span>
	 *                  <span class="zh-CN">是否简写IPv6地址</span>
	 * @return <span class="en-US">IPv6 address string</span>
	 * <span class="zh-CN">转换后的IPv6地址</span>
	 */
	public static String IPv4ToIPv6(@Nonnull final String ipAddress, final boolean collapse) {
		if (StringUtils.matches(ipAddress, RegexGlobals.IPV4_REGEX)) {
			String[] splitAddress = StringUtils.tokenizeToStringArray(ipAddress, SPLIT_CHARACTER_IPV4);
			StringBuilder stringBuilder;
			if (collapse) {
				stringBuilder = new StringBuilder(SPLIT_CHARACTER_IPV6);
			} else {
				stringBuilder = new StringBuilder("0000:0000:0000:0000:0000:0000");
			}
			int index = 0;
			for (String addressItem : splitAddress) {
				if (index % 2 == 0) {
					stringBuilder.append(SPLIT_CHARACTER_IPV6);
				}
				stringBuilder.append(Integer.toHexString(Integer.parseInt(addressItem)));
				index++;
			}

			return stringBuilder.toString().toUpperCase();
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Convert given IP address string to byte array</h3>
	 * <h3 class="zh-CN">转换给定的IP地址为字节数组</h3>
	 *
	 * @param ipAddress <span class="en-US">IP address string</span>
	 *                  <span class="zh-CN">IP地址字符串</span>
	 * @return <span class="en-US">Converted byte array</span>
	 * <span class="zh-CN">转换后的字节数组</span>
	 */
	public static byte[] IPToBytes(@Nonnull final String ipAddress) {
		if (StringUtils.matches(ipAddress, RegexGlobals.IPV4_REGEX)) {
			return IPv4ToBytes(ipAddress);
		} else if (StringUtils.matches(ipAddress, RegexGlobals.IPV6_REGEX)
				|| StringUtils.matches(ipAddress, RegexGlobals.IPV6_COMPRESS_REGEX)) {
			return IPv6ToBytes(ipAddress);
		} else {
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Convert given IPv4 address string to byte array</h3>
	 * <h3 class="zh-CN">转换给定的IPv4地址为字节数组</h3>
	 *
	 * @param ipAddress <span class="en-US">IPv4 address string</span>
	 *                  <span class="zh-CN">IPv4地址字符串</span>
	 * @return <span class="en-US">Converted byte array</span>
	 * <span class="zh-CN">转换后的字节数组</span>
	 */
	public static byte[] IPv4ToBytes(@Nonnull final String ipAddress) {
		if (StringUtils.matches(ipAddress, RegexGlobals.IPV4_REGEX)) {
			String[] splitAddress = StringUtils.tokenizeToStringArray(ipAddress, SPLIT_CHARACTER_IPV4);
			byte[] addressBytes = new byte[4];

			addressBytes[0] = (byte) Integer.parseInt(splitAddress[0]);
			addressBytes[1] = (byte) Integer.parseInt(splitAddress[1]);
			addressBytes[2] = (byte) Integer.parseInt(splitAddress[2]);
			addressBytes[3] = (byte) Integer.parseInt(splitAddress[3]);

			return addressBytes;
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Convert given IPv6 address string to byte array</h3>
	 * <h3 class="zh-CN">转换给定的IPv6地址为字节数组</h3>
	 *
	 * @param ipAddress <span class="en-US">IPv6 address string</span>
	 *                  <span class="zh-CN">IPv6地址字符串</span>
	 * @return <span class="en-US">Converted byte array</span>
	 * <span class="zh-CN">转换后的字节数组</span>
	 */
	public static byte[] IPv6ToBytes(@Nonnull final String ipAddress) {
		if (StringUtils.matches(ipAddress, RegexGlobals.IPV6_REGEX)
				|| StringUtils.matches(ipAddress, RegexGlobals.IPV6_COMPRESS_REGEX)) {
			String ipv6Address = expandIPv6(ipAddress);
			String[] splitAddress = StringUtils.tokenizeToStringArray(ipv6Address, SPLIT_CHARACTER_IPV6);
			byte[] addressBytes = new byte[16];
			int index = 0;
			for (String address : splitAddress) {
				int tmp = Integer.parseInt(address, 16);
				addressBytes[index] = (byte) (tmp >> 8);
				addressBytes[index + 1] = (byte) tmp;
				index += 2;
			}
			return addressBytes;
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Expand the given combo IPv6 address string</h3>
	 * <h3 class="zh-CN">展开给定的缩略IPv6地址字符串</h3>
	 *
	 * @param ipAddress <span class="en-US">Combo IPv6 address string</span>
	 *                  <span class="zh-CN">缩略的IPv6地址字符串</span>
	 * @return <span class="en-US">Expanded IPv6 address string</span>
	 * <span class="zh-CN">展开后的IPv6地址字符串</span>
	 */
	public static String expandIPv6(@Nonnull final String ipAddress) {
		if (StringUtils.matches(ipAddress, RegexGlobals.IPV6_COMPRESS_REGEX)) {
			int sigCount = StringUtils.countOccurrencesOf(ipAddress, SPLIT_CHARACTER_IPV6);
			int expandCount = 8 - sigCount;
			int position = 0;
			StringBuilder stringBuilder = new StringBuilder();
			while (true) {
				int index = ipAddress.indexOf(SPLIT_CHARACTER_IPV6, position);
				if (index == Globals.DEFAULT_VALUE_INT) {
					stringBuilder.append(SPLIT_CHARACTER_IPV6).append(ipAddress.substring(position));
					break;
				} else {
					if (index == position) {
						while (expandCount > 0) {
							stringBuilder.append(":0");
							expandCount--;
						}
					} else {
						stringBuilder.append(SPLIT_CHARACTER_IPV6).append(ipAddress, position, index);
					}
					position = index + 1;
				}
			}
			return stringBuilder.substring(1);
		}
		return ipAddress;
	}

	/**
	 * <h3 class="en-US">Convert given IP address string to BigInteger instance</h3>
	 * <h3 class="zh-CN">转换给定的IP地址为BigInteger实例对象</h3>
	 *
	 * @param ipAddress <span class="en-US">IP address string</span>
	 *                  <span class="zh-CN">IP地址字符串</span>
	 * @return <span class="en-US">Converted BigInteger instance</span>
	 * <span class="zh-CN">转换后的BigInteger实例对象</span>
	 */
	public static BigInteger IPtoBigInteger(@Nonnull final String ipAddress) {
		if (StringUtils.matches(ipAddress, RegexGlobals.IPV4_REGEX)) {
			return IPv4ToBigInteger(ipAddress);
		} else {
			return IPv6ToBigInteger(ipAddress);
		}
	}

	/**
	 * <h3 class="en-US">Convert given IPv4 address string to BigInteger instance</h3>
	 * <h3 class="zh-CN">转换给定的IPv4地址为BigInteger实例对象</h3>
	 *
	 * @param ipAddress <span class="en-US">IPv4 address string</span>
	 *                  <span class="zh-CN">IPv4地址字符串</span>
	 * @return <span class="en-US">Converted BigInteger instance</span>
	 * <span class="zh-CN">转换后的BigInteger实例对象</span>
	 */
	public static BigInteger IPv4ToBigInteger(@Nonnull final String ipAddress) {
		if (StringUtils.matches(ipAddress, RegexGlobals.IPV4_REGEX)) {
			String[] splitAddress = StringUtils.tokenizeToStringArray(ipAddress, SPLIT_CHARACTER_IPV4);
			if (splitAddress.length == 4) {
				long result = 0L;
				for (int i = 0; i < splitAddress.length; i++) {
					result += (Long.parseLong(splitAddress[i]) << 8 * (3 - i));
				}
				return BigInteger.valueOf(result);
			}
		}
		return BigInteger.ZERO;
	}

	/**
	 * <h3 class="en-US">Convert given IPv6address string to BigInteger instance</h3>
	 * <h3 class="zh-CN">转换给定的IPv6地址为BigInteger实例对象</h3>
	 *
	 * @param ipAddress <span class="en-US">IPv6 address string</span>
	 *                  <span class="zh-CN">IPv6地址字符串</span>
	 * @return <span class="en-US">Converted BigInteger instance</span>
	 * <span class="zh-CN">转换后的BigInteger实例对象</span>
	 */
	public static BigInteger IPv6ToBigInteger(@Nonnull final String ipAddress) {
		String fullAddress = expandIgnore(ipAddress);
		if (StringUtils.matches(fullAddress, RegexGlobals.IPV6_REGEX)) {
			String[] splitAddress = StringUtils.tokenizeToStringArray(fullAddress, SPLIT_CHARACTER_IPV6);
			BigInteger bigInteger = BigInteger.ZERO;
			int index = 0;
			for (String split : splitAddress) {
				BigInteger currentInteger;
				if (StringUtils.matches(split, RegexGlobals.IPV4_REGEX)) {
					currentInteger = IPv4ToBigInteger(split);
				} else {
					currentInteger = BigInteger.valueOf(Long.valueOf(split, 16));
				}
				if (currentInteger == null) {
					return BigInteger.ZERO;
				}
				bigInteger = bigInteger.add(currentInteger.shiftLeft(16 * (splitAddress.length - index - 1)));
				index++;
			}
			return bigInteger;
		}
		return BigInteger.ZERO;
	}

	/**
	 * <h3 class="en-US">Convert given BigInteger instance to IPv4 address string</h3>
	 * <h3 class="zh-CN">转换给定的BigInteger实例对象为IPv4地址字符串</h3>
	 *
	 * @param bigInteger <span class="en-US">BigInteger instance</span>
	 *                   <span class="zh-CN">BigInteger实例对象</span>
	 * @return <span class="en-US">Converted IPv4 address string</span>
	 * <span class="zh-CN">转换后的IPv4地址字符串</span>
	 */
	public static String BigIntegerToIPv4(@Nonnull final BigInteger bigInteger) {
		StringBuilder ipv4Address = new StringBuilder();
		BigInteger calcInteger = new BigInteger(bigInteger.toByteArray());
		BigInteger ff = BigInteger.valueOf(0xFFL);
		for (int i = 0; i < 4; i++) {
			ipv4Address.insert(0, SPLIT_CHARACTER_IPV4 + calcInteger.and(ff));
			calcInteger = calcInteger.shiftRight(8);
		}
		return ipv4Address.substring(1);
	}

	/**
	 * <h3 class="en-US">Convert given BigInteger instance to IPv6 address string</h3>
	 * <h3 class="zh-CN">转换给定的BigInteger实例对象为IPv6地址字符串</h3>
	 *
	 * @param bigInteger <span class="en-US">BigInteger instance</span>
	 *                   <span class="zh-CN">BigInteger实例对象</span>
	 * @return <span class="en-US">Converted IPv6 address string</span>
	 * <span class="zh-CN">转换后的IPv6地址字符串</span>
	 */
	public static String BigIntegerToIPv6Address(@Nonnull final BigInteger bigInteger) {
		StringBuilder ipv6Address = new StringBuilder();
		BigInteger calcInteger = new BigInteger(bigInteger.toByteArray());
		BigInteger ff = BigInteger.valueOf(0xFFFFL);
		for (int i = 0; i < 8; i++) {
			ipv6Address.insert(0, SPLIT_CHARACTER_IPV6 + calcInteger.and(ff).toString(16));
			calcInteger = calcInteger.shiftRight(16);
		}
		return ipv6Address.substring(1).replaceFirst(RegexGlobals.IPV6_COMPRESS_REGEX, SPLIT_COMBO_CHARACTER_IPV6);
	}

	/**
	 * <h3 class="en-US">Expand the given combo IPv6 address string and append 0</h3>
	 * <h3 class="zh-CN">展开给定的缩略IPv6地址字符串并填充0</h3>
	 *
	 * @param ipv6Address <span class="en-US">Combo IPv6 address string</span>
	 *                    <span class="zh-CN">缩略的IPv6地址字符串</span>
	 * @return <span class="en-US">Expanded IPv6 address string</span>
	 * <span class="zh-CN">展开后的IPv6地址字符串</span>
	 */
	public static String expandIgnore(@Nonnull final String ipv6Address) {
		String resultAddress = ipv6Address;
		if (resultAddress.contains("::")) {
			int count = StringUtils.countOccurrencesOf(resultAddress, SPLIT_CHARACTER_IPV6);
			resultAddress = StringUtils.replace(resultAddress, SPLIT_COMBO_CHARACTER_IPV6,
					":0000".repeat(Math.max(0, 8 - count)) + SPLIT_CHARACTER_IPV6);
			if (resultAddress.startsWith(SPLIT_CHARACTER_IPV6)) {
				resultAddress = "0000" + resultAddress;
			}
			if (resultAddress.endsWith(SPLIT_CHARACTER_IPV6)) {
				resultAddress += "0000";
			}
		}
		String[] addressItems = StringUtils.delimitedListToStringArray(resultAddress, SPLIT_CHARACTER_IPV6);
		StringBuilder stringBuilder = new StringBuilder();
		for (String addressItem : addressItems) {
			StringBuilder addressItemBuilder = new StringBuilder(addressItem);
			while (addressItemBuilder.length() < 4) {
				addressItemBuilder.insert(0, "0");
			}
			addressItem = addressItemBuilder.toString();
			stringBuilder.append(SPLIT_CHARACTER_IPV6).append(addressItem);
		}
		return stringBuilder.substring(1);
	}

	/**
	 * <h3 class="en-US">Calculate the begin IP address by given IP address and netmask string</h3>
	 * <h3 class="zh-CN">根据给定的IP地址和子网掩码字符串计算起始IP地址</h3>
	 *
	 * @param ipAddress <span class="en-US">IP address string</span>
	 *                  <span class="zh-CN">IP地址字符串</span>
	 * @param netmask   <span class="en-US">IP address</span>
	 *                  <span class="zh-CN">IP地址</span>
	 * @return <span class="en-US">Begin IPv4 address string</span>
	 * <span class="zh-CN">起始的IPv4地址字符串</span>
	 */
	private static String beginIPv4(@Nonnull final String ipAddress, @Nonnull final String netmask) {
		String[] addressItems = StringUtils.tokenizeToStringArray(ipAddress, SPLIT_CHARACTER_IPV4);
		String[] maskItems = StringUtils.tokenizeToStringArray(netmask, SPLIT_CHARACTER_IPV4);
		StringBuilder stringBuilder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			int itemValue = i < addressItems.length ? Integer.parseInt(addressItems[i])
					: Globals.INITIALIZE_INT_VALUE;
			int beginItem = itemValue & Integer.parseInt(maskItems[i]);
			if (itemValue == 0 && i == 3) {
				beginItem++;
			}
			stringBuilder.append(SPLIT_CHARACTER_IPV4).append(beginItem);
		}
		return stringBuilder.substring(1);
	}

	/**
	 * <h3 class="en-US">Calculate the end IP address by given IP address and netmask string</h3>
	 * <h3 class="zh-CN">根据给定的IP地址和子网掩码字符串计算起始IP地址</h3>
	 *
	 * @param beginIP <span class="en-US">Begin IP address string</span>
	 *                <span class="zh-CN">起始IP地址字符串</span>
	 * @param netmask <span class="en-US">IP address</span>
	 *                <span class="zh-CN">IP地址</span>
	 * @return <span class="en-US">End IPv4 address string</span>
	 * <span class="zh-CN">终止的IPv4地址字符串</span>
	 */
	private static String endIPv4(@Nonnull final String beginIP, @Nonnull final String netmask) {
		String[] addressItems = StringUtils.tokenizeToStringArray(beginIP, SPLIT_CHARACTER_IPV4);
		String[] maskItems = StringUtils.tokenizeToStringArray(netmask, SPLIT_CHARACTER_IPV4);
		StringBuilder stringBuilder = new StringBuilder();
		for (int i = 0; i < 4; i++) {
			int endItem = 255 - Integer.parseInt(addressItems[i]) ^ Integer.parseInt(maskItems[i]);
			stringBuilder.append(SPLIT_CHARACTER_IPV4).append(endItem);
		}
		return stringBuilder.substring(1);
	}

	/**
	 * <h3 class="en-US">Calculate the begin IPv6 address by given IP address and netmask string</h3>
	 * <h3 class="zh-CN">根据给定的IP地址和子网掩码字符串计算起始IP地址</h3>
	 *
	 * @param ipAddress <span class="en-US">IP address string</span>
	 *                  <span class="zh-CN">IP地址字符串</span>
	 * @param cidr      <span class="en-US">CIDR value</span>
	 *                  <span class="zh-CN">CIDR值</span>
	 * @return <span class="en-US">Begin IPv6 address string</span>
	 * <span class="zh-CN">起始的IPv6地址字符串</span>
	 */
	private static String beginIPv6(@Nonnull final String ipAddress, final int cidr) {
		if (cidr >= Globals.INITIALIZE_INT_VALUE && cidr <= 128) {
			String hexAddress = StringUtils.replace(expandIgnore(ipAddress), SPLIT_CHARACTER_IPV6, Globals.DEFAULT_VALUE_STRING);
			StringBuilder baseIP = new StringBuilder(hexToBin(hexAddress).substring(Globals.INITIALIZE_INT_VALUE, cidr));
			while (baseIP.length() < 128) {
				baseIP.append("0");
			}
			return binToHex(baseIP.toString());
		}
		return Globals.DEFAULT_VALUE_STRING;
	}

	/**
	 * <h3 class="en-US">Calculate the end IPv6 address by given begin IPv6 address and netmask string</h3>
	 * <h3 class="zh-CN">根据给定的IP地址和子网掩码字符串计算起始IP地址</h3>
	 *
	 * @param beginIP <span class="en-US">Begin IPv6 address string</span>
	 *                <span class="zh-CN">起始IPv6地址字符串</span>
	 * @param cidr    <span class="en-US">CIDR value</span>
	 *                <span class="zh-CN">CIDR值</span>
	 * @return <span class="en-US">End IPv6 address string</span>
	 * <span class="zh-CN">终止的IPv6地址字符串</span>
	 */
	private static String endIPv6(@Nonnull final String beginIP, final int cidr) {
		if (cidr >= Globals.INITIALIZE_INT_VALUE && cidr <= 128) {
			String hexAddress = StringUtils.replace(expandIgnore(beginIP), SPLIT_CHARACTER_IPV6, Globals.DEFAULT_VALUE_STRING);
			StringBuilder baseIP = new StringBuilder(hexToBin(hexAddress).substring(Globals.INITIALIZE_INT_VALUE, cidr));
			while (baseIP.length() < 128) {
				baseIP.append("1");
			}
			return binToHex(baseIP.toString());
		}
		return Globals.DEFAULT_VALUE_STRING;
	}

	/**
	 * <h3 class="en-US">Convert hex address to binary string</h3>
	 * <h3 class="zh-CN">转换16进制地址为二进制地址字符串</h3>
	 *
	 * @param hexAddress <span class="en-US">Hex address string</span>
	 *                   <span class="zh-CN">16进制地址字符串</span>
	 * @return <span class="en-US">Binary address string</span>
	 * <span class="zh-CN">二进制地址字符串</span>
	 */
	private static String hexToBin(@Nonnull final String hexAddress) {
		StringBuilder binBuilder = new StringBuilder();
		int index = 0;
		while (index < hexAddress.length()) {
			int hexInt = Integer.parseInt(hexAddress.substring(index, index + 1), 16);
			StringBuilder binItem = new StringBuilder(Integer.toString(hexInt, 2));
			while (binItem.length() < 4) {
				binItem.insert(0, "0");
			}
			binBuilder.append(binItem);
			index++;
		}
		return binBuilder.toString();
	}

	/**
	 * <h3 class="en-US">Convert binary address to hex string</h3>
	 * <h3 class="zh-CN">转换16进制地址为二进制地址字符串</h3>
	 *
	 * @param binAddress <span class="en-US">Binary address string</span>
	 *                   <span class="zh-CN">二进制地址字符串</span>
	 * @return <span class="en-US">Hex address string</span>
	 * <span class="zh-CN">16进制地址字符串</span>
	 */
	private static String binToHex(@Nonnull final String binAddress) {
		StringBuilder binBuilder = new StringBuilder();
		int index = 0;
		while (index < binAddress.length()) {
			if (index % 16 == 0) {
				binBuilder.append(SPLIT_CHARACTER_IPV6);
			}
			int binInt = Integer.parseInt(binAddress.substring(index, index + 4), 2);
			binBuilder.append(Integer.toString(binInt, 16).toUpperCase());
			index += 4;
		}
		return binBuilder.substring(1);
	}

	private static int fillBitsFromLeft(final int value) {
		if (value >= 8) {
			return 255;
		} else {
			return 256 - Double.valueOf(Math.pow(2, (8 - value))).intValue();
		}
	}
}
