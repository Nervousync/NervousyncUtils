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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.vladsch.flexmark.html.HtmlRenderer;
import com.vladsch.flexmark.parser.Parser;
import com.vladsch.flexmark.profile.pegdown.Extensions;
import com.vladsch.flexmark.profile.pegdown.PegdownOptionsAdapter;
import com.vladsch.flexmark.util.data.DataHolder;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.nervousync.annotations.beans.OutputConfig;
import org.nervousync.beans.transfer.cdata.CDataAdapter;
import org.nervousync.commons.Globals;
import org.nervousync.commons.RegexGlobals;
import org.nervousync.tree.huffman.HuffmanTree;
import org.w3c.dom.Document;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.io.*;
import java.lang.Character.UnicodeBlock;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <h2 class="en-US">String utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Encode byte arrays using Base32/Base64</ul>
 *     <ul>Decode Base32/Base64 string to byte arrays</ul>
 *     <ul>Encode string to a Huffman tree</ul>
 *     <ul>Trim given string</ul>
 *     <ul>Match given string is MD5 value/UUID/phone number/e-mail address etc.</ul>
 *     <ul>Check given string is empty/notNull/notEmpty/contains string etc.</ul>
 *     <ul>Tokenize string by given delimiters</ul>
 *     <ul>Substring given input string by rule</ul>
 *     <ul>Validate given string is match code type</ul>
 * </span>
 * <h2 class="zh-CN">字符串工具集</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>使用Base32/Base64编码给定的二进制字节数组</ul>
 *     <ul>将给定的Base32/Base64编码字符串解码为二进制字节数组</ul>
 *     <ul>将给定的字符串编码为霍夫曼树结果实例对象</ul>
 *     <ul>去除字符串中的空格</ul>
 *     <ul>检查给定的字符串是否为MD5值/UUID/电话号码/电子邮件地址等</ul>
 *     <ul>检查给定的字符串是否为空/非空/包含字符串等</ul>
 *     <ul>使用给定的分隔符分割字符串</ul>
 *     <ul>根据规则截取字符串</ul>
 *     <ul>验证给定的字符串是否符合代码类型</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Jan 13, 2010 15:53:41 $
 */
public final class StringUtils {
	/**
	 * <span class="en-US">Multilingual supported logger instance</span>
	 * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(StringUtils.class);
	/**
	 * <span class="en-US">Top folder path</span>
	 * <span class="zh-CN">上级目录路径</span>
	 */
	private static final String TOP_PATH = "..";
	/**
	 * <span class="en-US">Current folder path</span>
	 * <span class="zh-CN">当前目录路径</span>
	 */
	private static final String CURRENT_PATH = ".";
	/**
	 * <span class="en-US">Mask bytes using for convert number to unsigned number</span>
	 * <span class="zh-CN">掩码字节用于转换数字为无符号整形</span>
	 */
	private static final int MASK_BYTE_UNSIGNED = 0xFF;
	/**
	 * <span class="en-US">Padding byte of Base32/Base64</span>
	 * <span class="zh-CN">Base32/Base64的填充字节</span>
	 */
	private static final int PADDING = '=';
	/**
	 * <span class="en-US">Character string for Base32</span>
	 * <span class="zh-CN">Base32用到的字符</span>
	 */
	private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	/**
	 * <span class="en-US">Character string for Base64</span>
	 * <span class="zh-CN">Base64用到的字符</span>
	 */
	private static final String BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	/**
	 * <span class="en-US">Character string for authenticate code</span>
	 * <span class="zh-CN">验证码用到的字符</span>
	 */
	private static final String AUTHORIZATION_CODE_ITEMS = "23456789ABCEFGHJKLMNPQRSTUVWXYZ";
	/**
	 * <span class="en-US">End character of China ID code</span>
	 * <span class="zh-CN">中国身份证号的结尾字符</span>
	 */
	private static final String CHN_ID_CARD_CODE = "0123456789X";
	/**
	 * <span class="en-US">End character of China Social Credit code</span>
	 * <span class="zh-CN">中国统一信用代码的结尾字符</span>
	 */
	private static final String CHN_SOCIAL_CREDIT_CODE = "0123456789ABCDEFGHJKLMNPQRTUWXY";
	/**
	 * <span class="en-US">XML fragment template</span>
	 * <span class="zh-CN">XML声明模板</span>
	 */
	private static final String FRAGMENT_TEMPLATE = "<?xml version=\"1.0\" encoding=\"{}\"?>";
	/**
	 * <span class="en-US">XML Schema file mapping resource path</span>
	 * <span class="zh-CN">XML约束文档的资源映射文件</span>
	 */
	private static final String SCHEMA_MAPPING_RESOURCE_PATH = "META-INF/nervousync.schemas";
	/**
	 * <span class="en-US">Registered schema mapping</span>
	 * <span class="zh-CN">注册的约束文档与资源文件的映射</span>
	 */
	private static final Map<String, String> SCHEMA_MAPPING = new HashMap<>();

	static {
		try {
			ClassUtils.getDefaultClassLoader().getResources(SCHEMA_MAPPING_RESOURCE_PATH)
					.asIterator()
					.forEachRemaining(StringUtils::REGISTER_SCHEMA);
		} catch (IOException e) {
			LOGGER.error("Load_Schema_Mapping_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}
	}

	/**
	 * <h3 class="en-US">Encode byte arrays using Base32</h3>
	 * <span class="en-US">
	 * Will return zero length string for given byte arrays is <code>null</code> or arrays length is 0.
	 * </span>
	 * <h3 class="zh-CN">使用Base32编码给定的二进制字节数组</h3>
	 * <span class="zh-CN">如果给定的二进制字节数组为<code>null</code>或长度为0，将返回长度为0的空字符串</span>
	 * <pre>
	 * StringUtils.base32Encode(null) = ""
	 * StringUtils.base32Encode([]) = ""
	 * StringUtils.base32Encode([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]) = "JBSWY3DPEBLW64TMMQ"
	 * </pre>
	 *
	 * @param bytes <span class="en-US">byte arrays</span>
	 *              <span class="zh-CN">二进制字节数组</span>
	 * @return <span class="en-US">Encoded base32 string</span>
	 * <span class="zh-CN">编码后的Base32字符串</span>
	 */
	public static String base32Encode(final byte[] bytes) {
		return base32Encode(bytes, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Encode byte arrays using Base32</h3>
	 * <span class="en-US">
	 * Will append padding character at the end if parameter padding is <code>true</code>
	 * and result string length % 5 != 0.
	 * Will return zero length string for given byte arrays is <code>null</code> or arrays length is 0.
	 * </span>
	 * <h3 class="zh-CN">使用Base32编码给定的二进制字节数组</h3>
	 * <span class="zh-CN">
	 * 如果参数padding设置为<code>true</code>，并且结果字符串长度非5的整数倍，则自动追加填充字符到结果末尾。
	 * 如果给定的二进制字节数组为<code>null</code>或长度为0，将返回长度为0的空字符串
	 * </span>
	 * <pre>
	 * StringUtils.base32Encode(null, true) = ""
	 * StringUtils.base32Encode([], true) = ""
	 * StringUtils.base32Encode([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100], true) = "JBSWY3DPEBLW64TMMQ=="
	 * </pre>
	 *
	 * @param bytes   <span class="en-US">byte arrays</span>
	 *                <span class="zh-CN">二进制字节数组</span>
	 * @param padding <span class="en-US">append padding character status</span>
	 *                <span class="zh-CN">是否追加填充字符到结果末尾</span>
	 * @return <span class="en-US">Encoded base32 string</span>
	 * <span class="zh-CN">编码后的Base32字符串</span>
	 */
	public static String base32Encode(final byte[] bytes, boolean padding) {
		if (bytes == null) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		StringBuilder stringBuilder = new StringBuilder();

		int i = 0, index = 0;
		int currentByte, nextByte, digit;

		while (i < bytes.length) {
			currentByte = bytes[i] >= 0 ? bytes[i] : bytes[i] + 256;

			if (index > 3) {
				if ((i + 1) < bytes.length) {
					nextByte = bytes[i + 1] >= 0 ? bytes[i + 1] : bytes[i + 1] + 256;
				} else {
					nextByte = 0;
				}

				digit = currentByte & (MASK_BYTE_UNSIGNED >> index);
				index = (index + 5) % 8;
				digit = (digit << index) | nextByte >> (8 - index);
				i++;
			} else {
				digit = (currentByte >> (8 - (index + 5))) & 0x1F;
				index = (index + 5) % 8;
				if (index == 0) {
					i++;
				}
			}
			stringBuilder.append(BASE32.charAt(digit));
		}

		if (padding) {
			while (stringBuilder.length() % 5 > 0) {
				stringBuilder.append((char) PADDING);
			}
		}
		return stringBuilder.toString();
	}

	/**
	 * <h3 class="en-US">Decode given Base32 string to byte arrays</h3>
	 * <span class="en-US">
	 * Will return a zero-length array for given base64 string is <code>null</code> or string length is 0.
	 * </span>
	 * <h3 class="zh-CN">将给定的Base32编码字符串解码为二进制字节数组</h3>
	 * <span class="zh-CN">如果给定的字符串长度为0，则返回长度为0的二进制字节数组</span>
	 * <pre>
	 * StringUtils.base32Decode(null) = []
	 * StringUtils.base32Decode("") = []
	 * StringUtils.base32Decode("JBSWY3DPEBLW64TMMQ") = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
	 * </pre>
	 *
	 * @param string <span class="en-US">Encoded base32 string</span>
	 *               <span class="zh-CN">编码后的Base32字符串</span>
	 * @return <span class="en-US">Decoded byte array</span>
	 * <span class="zh-CN">解码后的二进制字节数组</span>
	 */
	public static byte[] base32Decode(String string) {
		if (string == null || string.isEmpty()) {
			return new byte[0];
		}

		while (string.charAt(string.length() - 1) == PADDING) {
			string = string.substring(0, string.length() - 1);
		}

		byte[] bytes = new byte[string.length() * 5 / 8];
		int index = 0;
		StringBuilder stringBuilder = new StringBuilder(8);
		StringBuilder temp;
		for (String c : string.split("")) {
			if (BASE32.contains(c)) {
				int current = BASE32.indexOf(c);
				temp = new StringBuilder(5);
				for (int i = 0; i < 5; i++) {
					temp.append(current & 1);
					current >>>= 1;
				}
				temp.reverse();
				if (stringBuilder.length() >= 3) {
					int currentLength = 8 - stringBuilder.length();
					stringBuilder.append(temp, 0, currentLength);
					bytes[index] = (byte) Integer.valueOf(stringBuilder.toString(), 2).intValue();
					index++;
					stringBuilder = new StringBuilder(8);
					stringBuilder.append(temp.substring(currentLength));
				} else {
					stringBuilder.append(temp);
				}
			}
		}
		return bytes;
	}

	/**
	 * <h3 class="en-US">Encode byte arrays using Base64</h3>
	 * <span class="en-US">
	 * Will return zero length string for given byte arrays is <code>null</code> or arrays length is 0.
	 * </span>
	 * <h3 class="zh-CN">使用Base64编码给定的二进制字节数组</h3>
	 * <span class="zh-CN">如果给定的二进制字节数组为<code>null</code>或长度为0，将返回长度为0的空字符串</span>
	 * <pre>
	 * StringUtils.base64Encode(null) = ""
	 * StringUtils.base64Encode([]) = ""
	 * StringUtils.base64Encode([72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]) = "SGVsbG8gV29ybGQ="
	 * </pre>
	 *
	 * @param bytes <span class="en-US">byte arrays</span>
	 *              <span class="zh-CN">二进制字节数组</span>
	 * @return <span class="en-US">Encoded Base64 string</span>
	 * <span class="zh-CN">编码后的Base64字符串</span>
	 */
	public static String base64Encode(final byte[] bytes) {
		if (bytes == null || bytes.length == 0) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		int length = bytes.length;
		byte[] tempBytes;
		if (length % 3 == 0) {
			tempBytes = bytes;
		} else {
			while (length % 3 != 0) {
				length++;
			}
			tempBytes = new byte[length];
			System.arraycopy(bytes, 0, tempBytes, 0, bytes.length);
			for (int i = bytes.length; i < length; i++) {
				tempBytes[i] = 0;
			}
		}

		StringBuilder stringBuilder = new StringBuilder();
		int index = 0;
		while ((index * 3) < length) {
			stringBuilder.append(BASE64.charAt((tempBytes[index * 3] >> 2) & 0x3F));
			stringBuilder.append(BASE64.charAt(((tempBytes[index * 3] << 4)
					| ((tempBytes[index * 3 + 1] & MASK_BYTE_UNSIGNED) >> 4)) & 0x3F));
			if (index * 3 + 1 < bytes.length) {
				stringBuilder.append(BASE64.charAt(((tempBytes[index * 3 + 1] << 2)
						| ((tempBytes[index * 3 + 2] & MASK_BYTE_UNSIGNED) >> 6)) & 0x3F));
			}
			if (index * 3 + 2 < bytes.length) {
				stringBuilder.append(BASE64.charAt(tempBytes[index * 3 + 2] & 0x3F));
			}
			index++;
		}

		while (stringBuilder.length() % 3 > 0) {
			stringBuilder.append((char) PADDING);
		}
		return stringBuilder.toString();
	}

	/**
	 * <h3 class="en-US">Decode given Base64 string to byte arrays</h3>
	 * <span class="en-US">
	 * Will return a zero-length array for given base64 string is <code>null</code> or string length is 0.
	 * </span>
	 * <h3 class="zh-CN">将给定的Base64编码字符串解码为二进制字节数组</h3>
	 * <span class="zh-CN">如果给定的字符串长度为0，则返回长度为0的二进制字节数组</span>
	 * <pre>
	 * StringUtils.base64Decode(null) = []
	 * StringUtils.base64Decode("") = []
	 * StringUtils.base64Decode("SGVsbG8gV29ybGQ=") = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]
	 * </pre>
	 *
	 * @param string <span class="en-US">Encoded Base64 string</span>
	 *               <span class="zh-CN">编码后的Base64字符串</span>
	 * @return <span class="en-US">Decoded byte array</span>
	 * <span class="zh-CN">解码后的二进制字节数组</span>
	 */
	public static byte[] base64Decode(final String string) {
		if (StringUtils.isEmpty(string)) {
			return new byte[0];
		}
		String origString = string;
		while (origString.charAt(origString.length() - 1) == PADDING) {
			origString = origString.substring(0, origString.length() - 1);
		}

		byte[] bytes = new byte[origString.length() * 3 / 4];

		int index = 0;
		for (int i = 0; i < origString.length(); i += 4) {
			int index1 = BASE64.indexOf(origString.charAt(i + 1));
			bytes[index * 3] = (byte) (((BASE64.indexOf(origString.charAt(i)) << 2) | (index1 >> 4)) & MASK_BYTE_UNSIGNED);
			if (index * 3 + 1 >= bytes.length) {
				break;
			}

			int index2 = BASE64.indexOf(origString.charAt(i + 2));
			bytes[index * 3 + 1] = (byte) (((index1 << 4) | (index2 >> 2)) & MASK_BYTE_UNSIGNED);
			if (index * 3 + 2 >= bytes.length) {
				break;
			}

			bytes[index * 3 + 2] = (byte) (((index2 << 6) | BASE64.indexOf(origString.charAt(i + 3))) & MASK_BYTE_UNSIGNED);
			index++;
		}

		return bytes;
	}

	/**
	 * <h3 class="en-US">Encoding given string to Huffman Tree string using given code mapping</h3>
	 * <h3 class="zh-CN">使用给定的编码映射表将给定的字符串编码为霍夫曼树结果字符串</h3>
	 *
	 * @param codeMapping <span class="en-US">Code mapping table</span>
	 *                    <span class="zh-CN">编码映射表</span>
	 * @param content     <span class="en-US">Content string</span>
	 *                    <span class="zh-CN">内容字符串</span>
	 * @return <span class="en-US">Generated huffman result string or zero length string if content string is empty</span>
	 * <span class="zh-CN">生成的霍夫曼树编码字符串，当内容字符串为空字符串时返回长度为0的空字符串</span>
	 */
	public static String encodeWithHuffman(final Hashtable<String, Object> codeMapping, final String content) {
		return HuffmanTree.encodeString(codeMapping, content);
	}

	/**
	 * <h3 class="en-US">Convert given string to Huffman Tree result instance</h3>
	 * <h3 class="zh-CN">将给定的字符串编码为霍夫曼树结果实例对象</h3>
	 *
	 * @param content <span class="en-US">Content string</span>
	 *                <span class="zh-CN">内容字符串</span>
	 * @return <span class="en-US">Generated huffman result instance or null if content string is empty</span>
	 * <span class="zh-CN">生成的霍夫曼结果实例对象，当内容字符串为空字符串时返回null</span>
	 */
	public static HuffmanTree.Result encodeWithHuffman(final String content) {
		HuffmanTree huffmanTree = new HuffmanTree();

		String temp = content;
		List<String> checkedStrings = new ArrayList<>();

		while (!temp.isEmpty()) {
			String keyword = temp.substring(0, 1);
			if (!checkedStrings.contains(keyword)) {
				huffmanTree.insertNode(new HuffmanTree.Node(keyword,
						StringUtils.countOccurrencesOf(content, keyword)));
				checkedStrings.add(keyword);
			}
			temp = temp.substring(1);
		}

		huffmanTree.build();
		return huffmanTree.encodeString(content);
	}

	/**
	 * <h3 class="en-US">Check that the given string is MD5 value</h3>
	 * <h3 class="zh-CN">检查给定的字符串是否符合MD5结果字符串格式</h3>
	 *
	 * @param string <span class="en-US">The given string will check</span>
	 *               <span class="zh-CN">将要检查的字符串</span>
	 * @return <span class="en-US"><code>true</code> if matched or <code>false</code> not match</span>
	 * <span class="zh-CN">检查匹配返回<code>true</code>，不匹配返回<code>false</code></span>
	 */
	@Deprecated
	public static boolean isMD5(final String string) {
		return StringUtils.notBlank(string) && StringUtils.matches(string.toLowerCase(), RegexGlobals.MD5_VALUE);
	}

	/**
	 * <h3 class="en-US">Check that the given string is UUID value</h3>
	 * <h3 class="zh-CN">检查给定的字符串是否符合UUID结果字符串格式</h3>
	 *
	 * @param string <span class="en-US">The given string will check</span>
	 *               <span class="zh-CN">将要检查的字符串</span>
	 * @return <span class="en-US"><code>true</code> if matched or <code>false</code> not match</span>
	 * <span class="zh-CN">检查匹配返回<code>true</code>，不匹配返回<code>false</code></span>
	 */
	public static boolean isUUID(final String string) {
		return StringUtils.notBlank(string) && StringUtils.matches(string.toLowerCase(), RegexGlobals.UUID);
	}

	/**
	 * <h3 class="en-US">Check that the given string is XML string</h3>
	 * <h3 class="zh-CN">检查给定的字符串是否符合XML字符串格式</h3>
	 *
	 * @param string <span class="en-US">The given string will check</span>
	 *               <span class="zh-CN">将要检查的字符串</span>
	 * @return <span class="en-US"><code>true</code> if matched or <code>false</code> not match</span>
	 * <span class="zh-CN">检查匹配返回<code>true</code>，不匹配返回<code>false</code></span>
	 */
	public static boolean isXML(final String string) {
		return StringUtils.notBlank(string) && StringUtils.matches(string, RegexGlobals.XML);
	}

	/**
	 * <h3 class="en-US">Check that the given string is Luhn string</h3>
	 * <h3 class="zh-CN">检查给定的字符串是否符合Luhn字符串格式</h3>
	 *
	 * @param string <span class="en-US">The given string will check</span>
	 *               <span class="zh-CN">将要检查的字符串</span>
	 * @return <span class="en-US"><code>true</code> if matched or <code>false</code> not match</span>
	 * <span class="zh-CN">检查匹配返回<code>true</code>，不匹配返回<code>false</code></span>
	 */
	public static boolean isLuhn(final String string) {
		return StringUtils.validateCode(string, CodeType.Luhn);
	}

	/**
	 * <h3 class="en-US">Check that the given string is China Social Credit Code string</h3>
	 * <h3 class="zh-CN">检查给定的字符串是否符合中国统一信用代码字符串格式</h3>
	 *
	 * @param string <span class="en-US">The given string will check</span>
	 *               <span class="zh-CN">将要检查的字符串</span>
	 * @return <span class="en-US"><code>true</code> if matched or <code>false</code> not match</span>
	 * <span class="zh-CN">检查匹配返回<code>true</code>，不匹配返回<code>false</code></span>
	 */
	public static boolean isChnSocialCredit(final String string) {
		return StringUtils.validateCode(string, CodeType.CHN_Social_Code);
	}

	/**
	 * <h3 class="en-US">Check that the given string is China ID Code string</h3>
	 * <h3 class="zh-CN">检查给定的字符串是否符合中国身份证号字符串格式</h3>
	 *
	 * @param string <span class="en-US">The given string will check</span>
	 *               <span class="zh-CN">将要检查的字符串</span>
	 * @return <span class="en-US"><code>true</code> if matched or <code>false</code> not match</span>
	 * <span class="zh-CN">检查匹配返回<code>true</code>，不匹配返回<code>false</code></span>
	 */
	public static boolean isChnId(final String string) {
		return StringUtils.validateCode(string, CodeType.CHN_ID_Code);
	}

	/**
	 * <h3 class="en-US">Check that the given string is phone number string</h3>
	 * <span class="en-US">Support country code start with 00 or +</span>
	 * <h3 class="zh-CN">检查给定的字符串是否符合电话号码字符串格式</h3>
	 * <span class="zh-CN">支持国家代码以00或+开头</span>
	 *
	 * @param string <span class="en-US">The given string will check</span>
	 *               <span class="zh-CN">将要检查的字符串</span>
	 * @return <span class="en-US"><code>true</code> if matched or <code>false</code> not match</span>
	 * <span class="zh-CN">检查匹配返回<code>true</code>，不匹配返回<code>false</code></span>
	 */
	public static boolean isPhoneNumber(final String string) {
		return StringUtils.notBlank(string) && StringUtils.matches(string, RegexGlobals.PHONE_NUMBER);
	}

	/**
	 * <h3 class="en-US">Check that the given string is SSN string</h3>
	 * <h3 class="zh-CN">检查给定的字符串是否符合美国社会安全码字符串格式</h3>
	 *
	 * @param string <span class="en-US">The given string will check</span>
	 *               <span class="zh-CN">将要检查的字符串</span>
	 * @return <span class="en-US"><code>true</code> if matched or <code>false</code> not match</span>
	 * <span class="zh-CN">检查匹配返回<code>true</code>，不匹配返回<code>false</code></span>
	 */
	public static boolean isSSN(final String string) {
		return StringUtils.notBlank(string)
				&& StringUtils.matches(string, RegexGlobals.US_Social_Security_Number);
	}

	/**
	 * <h3 class="en-US">Check that the given string is ITIN string</h3>
	 * <h3 class="zh-CN">检查给定的字符串是否符合美国个人纳税识别码字符串格式</h3>
	 *
	 * @param string <span class="en-US">The given string will check</span>
	 *               <span class="zh-CN">将要检查的字符串</span>
	 * @return <span class="en-US"><code>true</code> if matched or <code>false</code> not match</span>
	 * <span class="zh-CN">检查匹配返回<code>true</code>，不匹配返回<code>false</code></span>
	 */
	public static boolean isITIN(final String string) {
		return StringUtils.notBlank(string)
				&& StringUtils.matches(string, RegexGlobals.US_Individual_Taxpayer_Identification_Number);
	}

	/**
	 * <h3 class="en-US">Check that the given string is EIN string</h3>
	 * <h3 class="zh-CN">检查给定的字符串是否符合美国雇主身份识别码字符串格式</h3>
	 *
	 * @param string <span class="en-US">The given string will check</span>
	 *               <span class="zh-CN">将要检查的字符串</span>
	 * @return <span class="en-US"><code>true</code> if matched or <code>false</code> not match</span>
	 * <span class="zh-CN">检查匹配返回<code>true</code>，不匹配返回<code>false</code></span>
	 */
	public static boolean isEIN(final String string) {
		return StringUtils.notBlank(string)
				&& StringUtils.matches(string, RegexGlobals.US_Employer_Identification_Number);
	}

	/**
	 * <h3 class="en-US">Check that the given string is E-Mail string</h3>
	 * <h3 class="zh-CN">检查给定的字符串是否符合电子邮件字符串格式</h3>
	 *
	 * @param string <span class="en-US">The given string will check</span>
	 *               <span class="zh-CN">将要检查的字符串</span>
	 * @return <span class="en-US"><code>true</code> if matched or <code>false</code> not match</span>
	 * <span class="zh-CN">检查匹配返回<code>true</code>，不匹配返回<code>false</code></span>
	 */
	public static boolean isEMail(final String string) {
		return StringUtils.notBlank(string) && StringUtils.matches(string, RegexGlobals.EMAIL_ADDRESS);
	}

	/**
	 * <h3 class="en-US">Check that the given CharSequence is <code>null</code> or length 0.</h3>
	 * <span class="en-US">Will return <code>true</code> for a CharSequence that purely consists of blank.</span>
	 * <h3 class="zh-CN">检查给定的 CharSequence 是否为 <code>null</code> 或长度为 0。</h3>
	 * <span class="zh-CN">对于完全由空白组成的 CharSequence 将返回 <code>true</code>。</span>
	 * <pre>
	 * StringUtils.isEmpty(null) = true
	 * StringUtils.isEmpty(Globals.DEFAULT_VALUE_STRING) = true
	 * StringUtils.isEmpty(" ") = false
	 * StringUtils.isEmpty("Hello") = false
	 * </pre>
	 *
	 * @param str <span class="en-US">The CharSequence to check (maybe <code>null</code>)</span>
	 *            <span class="zh-CN">要检查的 CharSequence （可能 <code>null</code>）</span>
	 * @return <span class="en-US"><code>true</code> if the CharSequence is null or length 0.</span>
	 * <span class="zh-CN">如果 CharSequence 为 null 或长度为 0，则 <code>true</code></span>
	 */
	public static boolean isEmpty(final CharSequence str) {
		return !StringUtils.hasLength(str);
	}

	/**
	 * <h3 class="en-US">Check that the given CharSequence is neither <code>null</code> nor of length 0.</h3>
	 * <span class="en-US">Will return <code>true</code> for a CharSequence that purely consists of blank.</span>
	 * <h3 class="zh-CN">检查给定的 CharSequence 既不是 <code>null</code> 也不是长度为 0。</h3>
	 * <span class="zh-CN">对于完全由空白组成的 CharSequence 将返回 <code>true</code>。</span>
	 *
	 * <pre>
	 * StringUtils.notNull(null) = false
	 * StringUtils.notNull(Globals.DEFAULT_VALUE_STRING) = false
	 * StringUtils.notNull(" ") = true
	 * StringUtils.notNull("Hello") = true
	 * </pre>
	 *
	 * @param str <span class="en-US">The CharSequence to check (maybe <code>null</code>)</span>
	 *            <span class="zh-CN">要检查的 CharSequence （可能 <code>null</code>）</span>
	 * @return <span class="en-US"><code>true</code> if the CharSequence is not <code>null</code> and has length.</span>
	 * <span class="zh-CN">如果 CharSequence 不为<code>null</code>并且有长度，则为 <code>true</code></span>
	 */
	public static boolean notNull(final CharSequence str) {
		return (str != null && str.length() > 0);
	}

	/**
	 * <h3 class="en-US">Check that the given CharSequence is neither <code>null</code> nor only blank character.</h3>
	 * <span class="en-US">Will return <code>true</code> for a CharSequence that purely consists of blank.</span>
	 * <h3 class="zh-CN">检查给定的 CharSequence 既不是 <code>null</code> 也不是空白字符。</h3>
	 * <span class="zh-CN">对于完全由空白组成的 CharSequence 将返回 <code>true</code>。</span>
	 *
	 * <pre>
	 * StringUtils.notBlank(null) = false
	 * StringUtils.notBlank(Globals.DEFAULT_VALUE_STRING) = false
	 * StringUtils.notBlank(" ") = false
	 * StringUtils.notBlank("Hello") = true
	 * </pre>
	 *
	 * @param str <span class="en-US">the String to check (maybe <code>null</code>)</span>
	 *            <span class="zh-CN">要检查的字符串（可能 <code>null</code>）</span>
	 * @return <span class="en-US"><code>true</code> if the CharSequence is not <code>null</code> or blank character and has length.</span>
	 * <span class="zh-CN">如果 CharSequence 不是<code>null</code>或空白字符并且有长度，则<code>true</code></span>
	 */
	public static boolean notBlank(final String str) {
		return (str != null && !str.trim().isEmpty());
	}

	/**
	 * <h3 class="en-US">Check that the given CharSequence is neither <code>null</code> nor of length 0.</h3>
	 * <span class="en-US">Will return <code>true</code> for a CharSequence that purely consists of blank.</span>
	 * <h3 class="zh-CN">检查给定的 CharSequence 既不是 <code>null</code> 也不是长度为 0</h3>
	 * <span class="zh-CN">对于完全由空白组成的 CharSequence 将返回 <code>true</code>。</span>
	 *
	 * <pre>
	 * StringUtils.hasLength(null) = false
	 * StringUtils.hasLength(Globals.DEFAULT_VALUE_STRING) = false
	 * StringUtils.hasLength(" ") = true
	 * StringUtils.hasLength("Hello") = true
	 * </pre>
	 *
	 * @param str <span class="en-US">The CharSequence to check (maybe <code>null</code>)</span>
	 *            <span class="zh-CN">要检查的 CharSequence （可能 <code>null</code>）</span>
	 * @return <span class="en-US"><code>true</code> if the CharSequence is not <code>null</code> and has length.</span>
	 * <span class="zh-CN">如果 CharSequence 不为 <code>null</code> 并且有长度，则为 <code>true</code>。</span>
	 */
	public static boolean hasLength(final CharSequence str) {
		return (str != null && str.length() > 0);
	}

	/**
	 * <h3 class="en-US">Check whether the given CharSequence has actual text.</h3>
	 * <span class="en-US">
	 * More specifically, returns <code>true</code> if the string not <code>null</code>,
	 * its length is greater than 0, and it contains at least one non-blank character.
	 * </span>
	 * <h3 class="en-US">检查给定的 CharSequence 是否具有实际文本。</h3>
	 * <span class="zh-CN">
	 * 更具体地说，如果字符串不为 <code>null</code>、其长度大于 0，并且至少包含一个非空白字符，则返回 <code>true</code>。
	 * </span>
	 *
	 * @param str <span class="en-US">The CharSequence to check (maybe <code>null</code>)</span>
	 *            <span class="zh-CN">要检查的 CharSequence （可能 <code>null</code>）</span>
	 * @return <span class="en-US">
	 * <code>true</code> if the CharSequence is not <code>null</code>, its length is greater than 0,
	 * and it does not contain blank only
	 * </span>
	 * <span class="zh-CN"><code>true</code> 如果 CharSequence 不为 <code>null</code>，其长度大于 0，且不包含空白</span>
	 * @see java.lang.Character#isWhitespace java.lang.Character#isWhitespace
	 * <pre>
	 * StringUtils.hasText(null) = false
	 * StringUtils.hasText(Globals.DEFAULT_VALUE_STRING) = false
	 * StringUtils.hasText(" ") = false
	 * StringUtils.hasText("12345") = true
	 * StringUtils.hasText(" 12345 ") = true
	 * </pre>
	 */
	public static boolean hasText(final CharSequence str) {
		if (hasLength(str)) {
			return Boolean.FALSE;
		}
		int strLen = str.length();
		for (int i = 0; i < strLen; i++) {
			if (!Character.isWhitespace(str.charAt(i))) {
				return Boolean.TRUE;
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">returns the length of the string by detect encoding</h3>
	 * <span class="en-US">
	 * returns the length of the string by wrapping it in a byte buffer with
	 * the appropriate charset of the input string and returns the limit of the
	 * byte buffer
	 * </span>
	 * <h3 class="zh-CN">通过检测编码返回字符串的长度</h3>
	 * <span class="zh-CN">通过使用输入字符串的适当字符集将字符串包装在字节缓冲区中来返回字符串的长度，并返回字节缓冲区的限制</span>
	 *
	 * @param strIn <span class="en-US">the string</span>
	 *              <span class="zh-CN">输入字符串</span>
	 * @return <span class="en-US">length of the string</span>
	 * <span class="zh-CN">字符串长度</span>
	 */
	public static int encodedStringLength(final String strIn) {
		return encodedStringLength(strIn, detectCharset(strIn));
	}

	/**
	 * <h3 class="en-US">returns the length of the string in the input encoding</h3>
	 * <h3 class="zh-CN">返回输入编码中字符串的长度</h3>
	 *
	 * @param strIn   <span class="en-US">the string</span>
	 *                <span class="zh-CN">输入字符串</span>
	 * @param charset <span class="en-US">charset encoding</span>
	 *                <span class="zh-CN">charset encoding</span>
	 * @return <span class="en-US">length of the string</span>
	 * <span class="zh-CN">字符串长度</span>
	 */
	public static int encodedStringLength(final String strIn, final String charset) {
		if (StringUtils.isEmpty(strIn)) {
			return Globals.INITIALIZE_INT_VALUE;
		}
		if (StringUtils.isEmpty(charset)) {
			return Globals.DEFAULT_VALUE_INT;
		}
		ByteBuffer byteBuffer;
		try {
			byteBuffer = ByteBuffer.wrap(strIn.getBytes(charset));
		} catch (UnsupportedEncodingException e) {
			byteBuffer = ByteBuffer.wrap(strIn.getBytes(Charset.defaultCharset()));
		}

		return byteBuffer.limit();
	}

	/**
	 * <h3 class="en-US">Detects the encoding charset for the input string</h3>
	 * <h3 class="zh-CN">检测输入字符串的编码字符集</h3>
	 *
	 * @param strIn <span class="en-US">the string</span>
	 *              <span class="zh-CN">输入字符串</span>
	 * @return <span class="en-US">charset for the String</span>
	 * <span class="zh-CN">字符串的字符集</span>
	 */
	public static String detectCharset(final String strIn) {
		if (StringUtils.isEmpty(strIn)) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		try {
			String tempString = new String(strIn.getBytes(Globals.CHARSET_CP850), Globals.CHARSET_CP850);
			if (strIn.equals(tempString)) {
				return Globals.CHARSET_CP850;
			}
			tempString = new String(strIn.getBytes(Globals.CHARSET_GBK), Globals.CHARSET_GBK);
			if (strIn.equals(tempString)) {
				return Globals.CHARSET_GBK;
			}
			tempString = new String(strIn.getBytes(Globals.DEFAULT_ENCODING), Globals.DEFAULT_ENCODING);
			if (strIn.equals(tempString)) {
				return Globals.DEFAULT_ENCODING;
			}
		} catch (Exception e) {
			LOGGER.error("Detect_Charset_Error", strIn);
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}
		return Globals.DEFAULT_SYSTEM_CHARSET;
	}

	/**
	 * <h3 class="en-US">Check whether the given CharSequence contains any blank characters.</h3>
	 * <h3 class="zh-CN">检查给定的 CharSequence 是否包含任何空白字符。</h3>
	 *
	 * @param str <span class="en-US">The CharSequence to check (maybe <code>null</code>)</span>
	 *            <span class="zh-CN">要检查的 CharSequence （可能 <code>null</code>）</span>
	 * @return <span class="en-US"><code>true</code> if the CharSequence is not empty and contains at least 1 blank character</span>
	 * <span class="zh-CN">如果 CharSequence 不为空且包含至少 1 个空白字符，则为 <code>true</code></span>
	 * @see java.lang.Character#isWhitespace java.lang.Character#isWhitespace
	 */
	public static boolean containsWhitespace(final CharSequence str) {
		if (hasLength(str)) {
			return false;
		}
		int strLen = str.length();
		for (int i = 0; i < strLen; i++) {
			if (Character.isWhitespace(str.charAt(i))) {
				return true;
			}
		}
		return false;
	}

	/**
	 * <h3 class="en-US">Check whether the given String contains any blank characters.</h3>
	 * <h3 class="zh-CN">检查给定的字符串是否包含任何空白字符。</h3>
	 *
	 * @param str <span class="en-US">the String to check (maybe <code>null</code>)</span>
	 *            <span class="zh-CN">要检查的字符串（可能 <code>null</code>）</span>
	 * @return <span class="en-US"><code>true</code> if the String is not empty and contains at least one blank character.</span>
	 * <span class="zh-CN">如果字符串不为空且至少包含 1 个空白字符，则为 <code>true</code></span>
	 * @see #containsWhitespace(CharSequence) #containsWhitespace(CharSequence)
	 */
	public static boolean containsWhitespace(final String str) {
		return containsWhitespace((CharSequence) str);
	}

	/**
	 * <h3 class="en-US">Check whether the given String contains any blank characters.</h3>
	 * <h3 class="zh-CN">修剪给定字符串的前导和尾随空白。</h3>
	 *
	 * @param str <span class="en-US">the String to check</span>
	 *            <span class="zh-CN">要检查的字符串</span>
	 * @return <span class="en-US">the trimmed String</span>
	 * <span class="zh-CN">修剪后的字符串</span>
	 * @see java.lang.Character#isWhitespace java.lang.Character#isWhitespace
	 */
	public static String trimWhitespace(final String str) {
		String string = StringUtils.trimLeadingWhitespace(str);
		string = StringUtils.trimTrailingWhitespace(string);
		return string;
	}

	/**
	 * <h3 class="en-US">Trim all blank from the given String: leading, trailing, and in between characters.</h3>
	 * <h3 class="zh-CN">修剪给定字符串中的所有空白：前导、尾随和字符之间。</h3>
	 *
	 * @param str <span class="en-US">the String to check</span>
	 *            <span class="zh-CN">要检查的字符串</span>
	 * @return <span class="en-US">the trimmed String</span>
	 * <span class="zh-CN">修剪后的字符串</span>
	 * @see java.lang.Character#isWhitespace java.lang.Character#isWhitespace
	 */
	public static String trimAllWhitespace(final String str) {
		if (hasLength(str)) {
			return str;
		}
		StringBuilder buf = new StringBuilder(str);
		int index = 0;
		while (buf.length() > index) {
			if (Character.isWhitespace(buf.charAt(index))) {
				buf.deleteCharAt(index);
			} else {
				index++;
			}
		}
		return buf.toString();
	}

	/**
	 * <h3 class="en-US">Trim leading blank from the given String.</h3>
	 * <h3 class="zh-CN">修剪给定字符串中的前导空白。</h3>
	 *
	 * @param str <span class="en-US">the String to check</span>
	 *            <span class="zh-CN">要检查的字符串</span>
	 * @return <span class="en-US">the trimmed String</span>
	 * <span class="zh-CN">修剪后的字符串</span>
	 * @see java.lang.Character#isWhitespace java.lang.Character#isWhitespace
	 */
	public static String trimLeadingWhitespace(final String str) {
		if (hasLength(str)) {
			return str;
		}
		StringBuilder buf = new StringBuilder(str);
		while (buf.length() > 0 && Character.isWhitespace(buf.charAt(0))) {
			buf.deleteCharAt(0);
		}
		return buf.toString();
	}

	/**
	 * <h3 class="en-US">Trim trailing blank from the given String.</h3>
	 * <h3 class="zh-CN">修剪给定字符串中的尾随空白。</h3>
	 *
	 * @param str <span class="en-US">the String to check</span>
	 *            <span class="zh-CN">要检查的字符串</span>
	 * @return <span class="en-US">the trimmed String</span>
	 * <span class="zh-CN">修剪后的字符串</span>
	 * @see java.lang.Character#isWhitespace java.lang.Character#isWhitespace
	 */
	public static String trimTrailingWhitespace(final String str) {
		if (hasLength(str)) {
			return str;
		}
		StringBuilder buf = new StringBuilder(str);
		while (buf.length() > 0 && Character.isWhitespace(buf.charAt(buf.length() - 1))) {
			buf.deleteCharAt(buf.length() - 1);
		}
		return buf.toString();
	}

	/**
	 * <h3 class="en-US">Trim all occurrences of the supplied leading character from the given String.</h3>
	 * <h3 class="zh-CN">修剪给定字符串中所有出现的所提供的前导字符。</h3>
	 *
	 * @param str              <span class="en-US">the String to check</span>
	 *                         <span class="zh-CN">要检查的字符串</span>
	 * @param leadingCharacter <span class="en-US">the leading character to be trimmed</span>
	 *                         <span class="zh-CN">要修剪的前导字符</span>
	 * @return <span class="en-US">the trimmed String</span>
	 * <span class="zh-CN">修剪后的字符串</span>
	 */
	public static String trimLeadingCharacter(final String str, final char leadingCharacter) {
		if (hasLength(str)) {
			return str;
		}
		StringBuilder buf = new StringBuilder(str);
		while (buf.length() > 0 && buf.charAt(0) == leadingCharacter) {
			buf.deleteCharAt(0);
		}
		return buf.toString();
	}

	/**
	 * <h3 class="en-US">Trim all occurrences of the supplied trailing character from the given String.</h3>
	 * <h3 class="zh-CN">修剪给定字符串中所有出现的所提供的尾随字符。</h3>
	 *
	 * @param str               <span class="en-US">the String to check</span>
	 *                          <span class="zh-CN">要检查的字符串</span>
	 * @param trailingCharacter <span class="en-US">the trailing character to be trimmed</span>
	 *                          <span class="zh-CN">要修剪的尾随字符</span>
	 * @return <span class="en-US">the trimmed String</span>
	 * <span class="zh-CN">修剪后的字符串</span>
	 */
	public static String trimTrailingCharacter(final String str, final char trailingCharacter) {
		if (hasLength(str)) {
			return str;
		}
		StringBuilder buf = new StringBuilder(str);
		while (buf.length() > 0 && buf.charAt(buf.length() - 1) == trailingCharacter) {
			buf.deleteCharAt(buf.length() - 1);
		}
		return buf.toString();
	}

	/**
	 * <h3 class="en-US">Test if the given String starts with the specified prefix, ignoring the upper/lower case.</h3>
	 * <h3 class="zh-CN">测试给定的字符串是否以指定的前缀开头，忽略大小写。</h3>
	 *
	 * @param str    <span class="en-US">the String to check</span>
	 *               <span class="zh-CN">要检查的字符串</span>
	 * @param prefix <span class="en-US">the prefix to look for</span>
	 *               <span class="zh-CN">要查找的前缀</span>
	 * @return <span class="en-US">check result</span>
	 * <span class="zh-CN">检查结果</span>
	 * @see java.lang.String#startsWith java.lang.String#startsWith
	 */
	public static boolean startsWithIgnoreCase(final String str, final String prefix) {
		if (str == null || prefix == null) {
			return false;
		}
		if (str.startsWith(prefix)) {
			return true;
		}
		if (str.length() < prefix.length()) {
			return false;
		}
		String lcStr = str.substring(0, prefix.length()).toLowerCase();
		String lcPrefix = prefix.toLowerCase();
		return lcStr.equals(lcPrefix);
	}

	/**
	 * <h3 class="en-US">Test if the given String ends with the specified suffix, ignoring the upper/lower case.</h3>
	 * <h3 class="zh-CN">测试给定的字符串是否以指定的后缀结尾，忽略大小写。</h3>
	 *
	 * @param str    <span class="en-US">the String to check</span>
	 *               <span class="zh-CN">要检查的字符串</span>
	 * @param suffix <span class="en-US">the suffix to look for</span>
	 *               <span class="zh-CN">要查找的后缀</span>
	 * @return <span class="en-US">check result</span>
	 * <span class="zh-CN">检查结果</span>
	 * @see java.lang.String#endsWith java.lang.String#endsWith
	 */
	public static boolean endsWithIgnoreCase(final String str, final String suffix) {
		if (str == null || suffix == null) {
			return false;
		}
		if (str.endsWith(suffix)) {
			return true;
		}
		if (str.length() < suffix.length()) {
			return false;
		}

		String lcStr = str.substring(str.length() - suffix.length()).toLowerCase();
		String lcSuffix = suffix.toLowerCase();
		return lcStr.equals(lcSuffix);
	}

	/**
	 * <h3 class="en-US">Check given string contains emoji information.</h3>
	 * <h3 class="zh-CN">检查给定字符串是否包含表情符号信息。</h3>
	 *
	 * @param str <span class="en-US">the String to check</span>
	 *            <span class="zh-CN">要检查的字符串</span>
	 * @return <span class="en-US">check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean containsEmoji(final String str) {
		if (StringUtils.notBlank(str)) {
			int length = str.length();
			for (int i = 0; i < length; i++) {
				char c = str.charAt(i);
				if (0xd800 <= c && c <= 0xdbff) {
					if (length > 1) {
						char next = str.charAt(i + 1);
						int result = ((c - 0xd800) * 0x400) + (next - 0xdc00) + 0x10000;
						if (0x1d000 <= result && result <= 0x1f77f) {
							return true;
						}
					}
				} else {
					if ((0x2100 <= c && c <= 0x27ff && c != 0x263b)
							|| (0x2805 <= c && c <= 0x2b07)
							|| (0x3297 <= c && c <= 0x3299)
							|| c == 0xa9 || c == 0xae || c == 0x303d
							|| c == 0x3030 || c == 0x2b55 || c == 0x2b1c
							|| c == 0x2b1b || c == 0x2b50) {
						return true;
					}

					if (length > 1 && i < (length - 1)) {
						char next = str.charAt(i + 1);
						if (next == 0x20e3) {
							return true;
						}
					}
				}
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Test whether the given string matches the given substring at the given index.</h3>
	 * <h3 class="zh-CN">测试给定字符串是否与给定索引处的给定子字符串匹配。</h3>
	 *
	 * @param str       <span class="en-US">the original string (or StringBuilder)</span>
	 *                  <span class="zh-CN">原始字符串（或 StringBuilder）</span>
	 * @param index     <span class="en-US">the index in the original string to start matching against</span>
	 *                  <span class="zh-CN">原始字符串中开始匹配的索引</span>
	 * @param substring <span class="en-US">the substring to match at the given index</span>
	 *                  <span class="zh-CN">在给定索引处匹配的子字符串</span>
	 * @return <span class="en-US">check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean substringMatch(final CharSequence str, final int index, final CharSequence substring) {
		for (int j = 0; j < substring.length(); j++) {
			int i = index + j;
			if (i >= str.length() || str.charAt(i) != substring.charAt(j)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * <h3 class="en-US">Count the occurrences of the substring in search string.</h3>
	 * <h3 class="zh-CN">计算搜索字符串中子字符串的出现次数。</h3>
	 *
	 * @param str <span class="en-US">string to search in. Return 0 if this is null.</span>
	 *            <span class="zh-CN">搜索的字符串。如果为 null，则返回 0。</span>
	 * @param sub <span class="en-US">string to search for. Return 0 if this is null.</span>
	 *            <span class="zh-CN">要搜索的子字符串。如果为 null，则返回 0。</span>
	 * @return <span class="en-US">count result</span>
	 * <span class="zh-CN">计数结果</span>
	 */
	public static int countOccurrencesOf(final String str, final String sub) {
		if (str == null || sub == null || str.isEmpty() || sub.isEmpty()) {
			return 0;
		}
		int count = 0, pos = 0, idx;
		while ((idx = str.indexOf(sub, pos)) != -1) {
			++count;
			pos = idx + sub.length();
		}
		return count;
	}

	/**
	 * <h3 class="en-US">Replace all occurrences of a substring within a string with another string.</h3>
	 * <h3 class="zh-CN">将字符串中所有出现的子字符串替换为另一个字符串。</h3>
	 *
	 * @param inString   <span class="en-US">String to examine</span>
	 *                   <span class="zh-CN">要检查的字符串</span>
	 * @param oldPattern <span class="en-US">String to replace</span>
	 *                   <span class="zh-CN">要替换的字符串</span>
	 * @param newPattern <span class="en-US">String to insert</span>
	 *                   <span class="zh-CN">替换后的字符串</span>
	 * @return <span class="en-US">String with the replacements</span>
	 * <span class="zh-CN">替换后的字符串</span>
	 */
	public static String replace(final String inString, final String oldPattern, final String newPattern) {
		if (inString == null || oldPattern == null || newPattern == null) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		StringBuilder stringBuilder = new StringBuilder();
		// output StringBuilder we'll build up
		int pos = 0; // our position in the old string
		int index = inString.indexOf(oldPattern);
		// the index of an occurrence we've found, or -1
		int patLen = oldPattern.length();
		while (index >= 0) {
			stringBuilder.append(inString, pos, index);
			stringBuilder.append(newPattern);
			pos = index + patLen;
			index = inString.indexOf(oldPattern, pos);
		}
		stringBuilder.append(inString.substring(pos));
		// remember to append any characters to the right of a match
		return stringBuilder.toString();
	}

	/**
	 * <h3 class="en-US">Delete all occurrences of the given substring.</h3>
	 * <h3 class="zh-CN">删除所有出现的给定子字符串。</h3>
	 *
	 * @param inString <span class="en-US">String to examine</span>
	 *                 <span class="zh-CN">要检查的字符串</span>
	 * @param pattern  <span class="en-US">the pattern to delete all occurrences of</span>
	 *                 <span class="zh-CN">要删除的出现模式</span>
	 * @return <span class="en-US">String with the deleted</span>
	 * <span class="zh-CN">删除后的字符串</span>
	 */
	public static String delete(final String inString, final String pattern) {
		return replace(inString, pattern, Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * <h3 class="en-US">Delete any character in a given String.</h3>
	 * <h3 class="zh-CN">删除给定字符串中的任何字符。</h3>
	 *
	 * @param inString      <span class="en-US">String to examine</span>
	 *                      <span class="zh-CN">要检查的字符串</span>
	 * @param charsToDelete <span class="en-US">a set of characters to delete. E.g. "az\n" will delete 'a's, 'z's and new lines.</span>
	 *                      <span class="zh-CN">要删除的一组字符。例如。 "az\n" 将删除 'a'、'z' 和换行符。</span>
	 * @return <span class="en-US">String with the deleted</span>
	 * <span class="zh-CN">删除后的字符串</span>
	 */
	public static String deleteAny(final String inString, final String charsToDelete) {
		if (hasLength(inString) || hasLength(charsToDelete)) {
			return inString;
		}
		StringBuilder out = new StringBuilder();
		for (int i = 0; i < inString.length(); i++) {
			char c = inString.charAt(i);
			if (charsToDelete.indexOf(c) == -1) {
				out.append(c);
			}
		}
		return out.toString();
	}

	/**
	 * <h3 class="en-US">Quote the given String with single quotes.</h3>
	 * <h3 class="zh-CN">用单引号引用给定的字符串。</h3>
	 *
	 * @param str <span class="en-US">the input String (e.g. "myString")</span>
	 *            <span class="zh-CN">输入字符串（例如"myString"）</span>
	 * @return <span class="en-US">the quoted String (e.g. "'myString'"), or <code>null</code> if the input was <code>null</code></span>
	 * <span class="zh-CN">带引号的字符串（例如“'myString'“），如果输入为 <code>null</code>，则为 <code>null</code></span>
	 */
	public static String quote(final String str) {
		return (str != null ? "'" + str + "'" : null);
	}

	/**
	 * <h3 class="en-US">Turn the given Object into a String with single quotes if it is a String; keeping the Object as-is else.</h3>
	 * <h3 class="zh-CN">如果给定的对象是字符串，则将其转换为带单引号的字符串；保持对象原样。</h3>
	 *
	 * @param obj <span class="en-US">the input Object (e.g. "myString")</span>
	 *            <span class="zh-CN">输入对象（例如"myString"）</span>
	 * @return <span class="en-US">the quoted String (e.g. "'myString'"), or the input object as-is if not a String</span>
	 * <span class="zh-CN">带引号的字符串（例如"'myString'"），或者如果不是字符串则按原样输入对象</span>
	 */
	public static Object quoteIfString(final Object obj) {
		return (obj instanceof String ? quote((String) obj) : obj);
	}

	/**
	 * <h3 class="en-US">
	 * Unqualified a string qualified by a '.' dot character.
	 * For example, "this.name.is.qualified", returns "qualified".
	 * </h3>
	 * <h3 class="zh-CN">返回由“.”分割名称的最后一段字符串。例如，"this.name.is.qualified"返回"qualified"。</h3>
	 *
	 * @param qualifiedName <span class="en-US">the qualified name</span>
	 *                      <span class="zh-CN">要分割的名称</span>
	 * @return <span class="en-US">qualified string</span>
	 * <span class="zh-CN">分割后的字符串</span>
	 */
	public static String unqualified(final String qualifiedName) {
		return unqualified(qualifiedName, '.');
	}

	/**
	 * <h3 class="en-US">
	 * Unqualified a string qualified by a separator character.
	 * For example, "this:name:is:qualified" returns "qualified" if using a ':' separator.
	 * </h3>
	 * <h3 class="zh-CN">返回由指定分隔符分割名称的最后一段字符串。例如，"this:name:is:qualified"如果使用":"分割则返回"qualified"。</h3>
	 *
	 * @param qualifiedName <span class="en-US">the qualified name</span>
	 *                      <span class="zh-CN">要分割的名称</span>
	 * @param separator     <span class="en-US">the separator</span>
	 *                      <span class="zh-CN">分隔符</span>
	 * @return <span class="en-US">qualified string</span>
	 * <span class="zh-CN">分割后的字符串</span>
	 */
	public static String unqualified(final String qualifiedName, final char separator) {
		return qualifiedName.substring(qualifiedName.lastIndexOf(separator) + 1);
	}

	/**
	 * <h3 class="en-US">changing the first letter to the upper case</h3>
	 * <h3 class="zh-CN">转换字符串的第一个字符为大写</h3>
	 *
	 * @param str <span class="en-US">the String to capitalize, maybe <code>null</code></span>
	 *            <span class="zh-CN">要大写的字符串，可能为 null</span>
	 * @return <span class="en-US">the capitalized String, or <code>null</code> if parameter str is <code>null</code></span>
	 * <span class="zh-CN">大写字符串，如果参数 str 为 <code>null</code>，则为 <code>null</code></span>
	 */
	public static String capitalize(final String str) {
		return changeFirstCharacterCase(str, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">changing the first letter to the lower case</h3>
	 * <h3 class="zh-CN">转换字符串的第一个字符为小写</h3>
	 *
	 * @param str <span class="en-US">the String to uncapitalize, maybe <code>null</code></span>
	 *            <span class="zh-CN">要小写的字符串，可能为 null</span>
	 * @return <span class="en-US">the uncapitalized String, or <code>null</code> if parameter str is <code>null</code></span>
	 * <span class="zh-CN">小写字符串，如果参数 str 为 <code>null</code>，则为 <code>null</code></span>
	 */
	public static String uncapitalized(final String str) {
		return changeFirstCharacterCase(str, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Extract the filename from the given path, e.g. "mypath/myfile.txt" -> "myfile.txt".</h3>
	 * <h3 class="zh-CN">从给定路径中提取文件名，例如“mypath/myfile.txt”->“myfile.txt”。</h3>
	 *
	 * @param path <span class="en-US">the file path (maybe <code>null</code>)</span>
	 *             <span class="zh-CN">文件路径（可能<code>null</code>）</span>
	 * @return <span class="en-US">the extracted filename, or <code>null</code> if none</span>
	 * <span class="zh-CN">提取的文件名，如果没有则为 <code>null</code></span>
	 */
	public static String getFilename(final String path) {
		if (path == null) {
			return null;
		}
		String cleanPath = cleanPath(path);
		int separatorIndex = cleanPath.lastIndexOf(Globals.DEFAULT_PAGE_SEPARATOR);
		return (separatorIndex != -1 ? cleanPath.substring(separatorIndex + 1) : cleanPath);
	}

	/**
	 * <h3 class="en-US">Extract the filename extension from the given path, e.g. "mypath/myfile.txt" -> "txt".</h3>
	 * <h3 class="zh-CN">从给定路径中提取文件扩展名，例如“mypath/myfile.txt”->“txt”。</h3>
	 *
	 * @param path <span class="en-US">the file path (maybe <code>null</code>)</span>
	 *             <span class="zh-CN">文件路径（可能<code>null</code>）</span>
	 * @return <span class="en-US">the extracted filename extension, or <code>null</code> if none</span>
	 * <span class="zh-CN">提取的文件扩展名，如果没有则为 <code>null</code></span>
	 */
	public static String getFilenameExtension(final String path) {
		if (path == null) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		int sepIndex = path.lastIndexOf(Globals.EXTENSION_SEPARATOR);
		return (sepIndex != -1 ? path.substring(sepIndex + 1) : Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * <h3 class="en-US">Strip the filename extension from the given path, e.g. "mypath/myfile.txt" -> "mypath/myfile".</h3>
	 * <h3 class="zh-CN">从给定路径中去除文件扩展名，例如“mypath/myfile.txt”->“mypath/myfile”。</h3>
	 *
	 * @param path <span class="en-US">the file path (maybe <code>null</code>)</span>
	 *             <span class="zh-CN">文件路径（可能<code>null</code>）</span>
	 * @return <span class="en-US">the path with stripped filename extension, or <code>null</code> if none</span>
	 * <span class="zh-CN">剥离文件扩展名后的路径，如果没有则为 <code>null</code></span>
	 */
	public static String stripFilenameExtension(final String path) {
		if (path == null) {
			return null;
		}
		int sepIndex = path.lastIndexOf(Globals.EXTENSION_SEPARATOR);
		return (sepIndex != -1 ? path.substring(0, sepIndex) : path);
	}

	/**
	 * <h3 class="en-US">Apply the given relative path to the given path, assuming standard Java folder separation (i.e. "/" separators)</h3>
	 * <h3 class="zh-CN">将给定的相对路径应用于给定的路径，假设标准 Java 文件夹分隔（即“/”分隔符）</h3>
	 *
	 * @param path         <span class="en-US">the path to start from (usually a full file path)</span>
	 *                     <span class="zh-CN">起始路径（通常是完整文件路径）</span>
	 * @param relativePath <span class="en-US">the relative path to apply (relative to the full file path above)</span>
	 *                     <span class="zh-CN">要应用的相对路径（相对于上面的完整文件路径）</span>
	 * @return <span class="en-US">the full file path that results from applying the relative path</span>
	 * <span class="zh-CN">应用相对路径产生的完整文件路径</span>
	 */
	public static String applyRelativePath(final String path, final String relativePath) {
		int separatorIndex = path.lastIndexOf(Globals.DEFAULT_PAGE_SEPARATOR);
		if (separatorIndex != -1) {
			String newPath = path.substring(0, separatorIndex);
			if (!relativePath.startsWith(Globals.DEFAULT_PAGE_SEPARATOR)) {
				newPath += Globals.DEFAULT_PAGE_SEPARATOR;
			}
			return newPath + relativePath;
		} else {
			return relativePath;
		}
	}

	/**
	 * <h3 class="en-US">Convert Markdown string to HTML code</h3>
	 * <h3 class="zh-CN">转换Markdown字符串为HTML代码</h3>
	 *
	 * @param markdown <span class="en-US">Markdown string</span>
	 *                 <span class="zh-CN">Markdown字符串</span>
	 * @return <span class="en-US">Converted HTML code</span>
	 * <span class="zh-CN">转换后的HTML代码</span>
	 */
	public static String mdToHtml(final String markdown) {
		DataHolder options = PegdownOptionsAdapter.flexmarkOptions(Boolean.TRUE, Extensions.ALL);
		Parser parser = Parser.builder(options).build();
		HtmlRenderer render = HtmlRenderer.builder(options).build();
		return render.render(parser.parse(markdown));
	}

	/**
	 * <h3 class="en-US">Normalize the path by suppressing sequences like "path/.." and inner simple dots.</h3>
	 * <span class="en-US">
	 * The result is convenient for path comparison. For other uses, notice that Windows separators ("\") are replaced by simple slashes.
	 * </span>
	 * <h3 class="zh-CN">转换给定字符串中的相对路径为标准路径</h3>
	 * <span class="zh-CN">结果便于路径比较。对于其他用途，请注意 Windows 分隔符（“\”）被简单的斜杠替换。</span>
	 *
	 * @param path <span class="en-US">the original path</span>
	 *             <span class="zh-CN">原始路径</span>
	 * @return <span class="en-US">the normalized path</span>
	 * <span class="zh-CN">标准化路径</span>
	 */
	public static String cleanPath(final String path) {
		String pathToUse = path;

		// Strip prefix from path to analyze, to not treat it as part of the
		// first path element. This is necessary to correctly parse paths like
		// "file:core/../core/io/Resource.class", where the ".." Should
		// strip the first "core" directory while keeping the "file:" prefix.
		int prefixIndex = pathToUse.indexOf(":");
		String prefix = Globals.DEFAULT_VALUE_STRING;
		if (prefixIndex != -1) {
			prefix = pathToUse.substring(0, prefixIndex + 1);
			pathToUse = pathToUse.substring(prefixIndex + 1);
		}
		String[] pathArray = delimitedListToStringArray(pathToUse, Globals.DEFAULT_PAGE_SEPARATOR);
		List<String> pathElements = new LinkedList<>();
		int tops = 0;
		for (int i = pathArray.length - 1; i >= 0; i--) {
			if (!CURRENT_PATH.equals(pathArray[i])) {
				if (TOP_PATH.equals(pathArray[i])) {
					// Registering the top path found.
					tops++;
				} else {
					if (tops > 0) {
						// Merging the path element with corresponding to the top path.
						tops--;
					} else {
						// Normal path element found.
						pathElements.add(0, pathArray[i]);
					}
				}
			}
		}
		// Remaining top paths need to be retained.
		for (int i = 0; i < tops; i++) {
			pathElements.add(0, TOP_PATH);
		}
		return prefix + collectionToDelimitedString(pathElements, Globals.DEFAULT_PAGE_SEPARATOR);
	}

	/**
	 * <h3 class="en-US">Compare two paths after normalization of them.</h3>
	 * <h3 class="zh-CN">比较标准化后的两条路径。</h3>
	 *
	 * @param path1 <span class="en-US">first path for comparison</span>
	 *              <span class="zh-CN">第一条比较路径</span>
	 * @param path2 <span class="en-US">second path for comparison</span>
	 *              <span class="zh-CN">第二条比较路径</span>
	 * @return <span class="en-US">Compare result</span>
	 * <span class="zh-CN">比较结果</span>
	 */
	public static boolean pathEquals(final String path1, final String path2) {
		return cleanPath(path1).equals(cleanPath(path2));
	}

	/**
	 * <h3 class="en-US">Parse the given <code>localeString</code> into a <code>Locale</code>.</h3>
	 * <h3 class="zh-CN">将给定的 <code>localeString</code> 解析为 <code>Locale</code>。</h3>
	 *
	 * @param localeString <span class="en-US">
	 *                     the locale string, following <code>Locale's</code> <code>toString()</code>
	 *                     format ("en", "en_UK", etc.);
	 *                     also accepts spaces as separators, as an alternative to underscore
	 *                     </span>
	 *                     <span class="zh-CN">
	 *                     语言环境字符串，遵循 <code>Locale's</code> <code>toString()</code> 格式（“en”、“en_UK” 等）；
	 *                     还接受空格作为分隔符替换下划线分隔符
	 *                     </span>
	 * @return <span class="en-US">a corresponding <code>Locale</code> instance</span>
	 * <span class="zh-CN">相应的 <code>Locale</code> 实例</span>
	 */
	public static Locale parseLocaleString(final String localeString) {
		if (localeString == null) {
			return null;
		}
		String[] parts = tokenizeToStringArray(localeString, "_", false, false);

		if (parts == null) {
			return null;
		}

		String language = (parts.length > 0 ? parts[0] : Globals.DEFAULT_VALUE_STRING);
		String country = (parts.length > 1 ? parts[1] : Globals.DEFAULT_VALUE_STRING);
		String variant = Globals.DEFAULT_VALUE_STRING;
		if (parts.length >= 2) {
			// There is definitely a variant, and it is everything after the country
			// code sans the separator between the country code and the variant.
			int endIndexOfCountryCode = localeString.indexOf(country) + country.length();
			// Strip off any leading '_' and blank, what's left is the variant.
			variant = trimLeadingWhitespace(localeString.substring(endIndexOfCountryCode));
			if (variant.startsWith("_")) {
				variant = trimLeadingCharacter(variant, '_');
			}
		}
		return (!language.isEmpty() ? new Locale(language, country, variant) : null);
	}
	//---------------------------------------------------------------------
	// Convenience methods for working with String arrays
	//---------------------------------------------------------------------

	/**
	 * <h3 class="en-US">Append the given String to the given String array</h3>
	 * <span class="en-US">returning a new array consisting of the input array contents plus the given String.</span>
	 * <h3 class="zh-CN">将给定的字符串附加到给定的字符串数组</h3>
	 * <span class="zh-CN">返回一个由输入数组内容加上给定字符串组成的新数组。</span>
	 *
	 * @param array <span class="en-US">the array to append to (can be <code>null</code>)</span>
	 *              <span class="zh-CN">要附加到的数组（可以为 <code>null</code>）</span>
	 * @param str   <span class="en-US">the String to append</span>
	 *              <span class="zh-CN">要附加的字符串</span>
	 * @return <span class="en-US">the new array (never <code>null</code>)</span>
	 * <span class="zh-CN">新数组（不会为<code>null</code>）</span>
	 */
	public static String[] addStringToArray(final String[] array, final String str) {
		if (CollectionUtils.isEmpty(array)) {
			return new String[]{str};
		}
		String[] newArr = new String[array.length + 1];
		System.arraycopy(array, 0, newArr, 0, array.length);
		newArr[array.length] = str;
		return newArr;
	}

	/**
	 * <h3 class="en-US">Concatenate the given String arrays into one</h3>
	 * <span class="en-US">With overlapping array elements included twice. The order of elements in the original arrays is preserved.</span>
	 * <h3 class="zh-CN">将给定的字符串数组连接成一个字符串</h3>
	 * <span class="zh-CN">重叠的数组元素包含两次。原始数组中元素的顺序被保留。</span>
	 *
	 * @param array1 <span class="en-US">the first array (can be <code>null</code>)</span>
	 *               <span class="zh-CN"></span>
	 * @param array2 <span class="en-US">the second array (can be <code>null</code>)</span>
	 *               <span class="zh-CN">第二个数组（可以为 <code>null</code>）</span>
	 * @return <span class="en-US">the new array (<code>null</code> if both given arrays were <code>null</code>)</span>
	 * <span class="zh-CN">新数组（如果两个给定数组均为 <code>null</code>，则为 <code>null</code>）</span>
	 */
	public static String[] concatenateStringArrays(final String[] array1, final String[] array2) {
		if (array1 == null) {
			return array2;
		}
		if (array2 == null) {
			return array1;
		}
		if (CollectionUtils.isEmpty(array1) && CollectionUtils.isEmpty(array2)) {
			return new String[0];
		}
		String[] newArr = new String[array1.length + array2.length];
		System.arraycopy(array1, 0, newArr, 0, array1.length);
		System.arraycopy(array2, 0, newArr, array1.length, array2.length);
		return newArr;
	}

	/**
	 * <h3 class="en-US">Merge the given String arrays into one</h3>
	 * <span class="en-US">
	 * With overlapping array elements only included once.
	 * The order of elements in the original arrays is preserved
	 * (except for overlapping elements, which are only included on their first occurrence).
	 * </span>
	 * <h3 class="zh-CN">将给定的字符串数组合并为一个字符串数组</h3>
	 * <span class="zh-CN">重叠的数组元素包含两次。原始数组中元素的顺序被保留（重叠元素除外，这些元素仅在第一次出现时包含在内）。</span>
	 *
	 * @param array1 <span class="en-US">the first array (can be <code>null</code>)</span>
	 *               <span class="zh-CN">第一个数组（可以为 <code>null</code>）</span>
	 * @param array2 <span class="en-US">the second array (can be <code>null</code>)</span>
	 *               <span class="zh-CN">第二个数组（可以为 <code>null</code>）</span>
	 * @return <span class="en-US">the new array (<code>null</code> if both given arrays were <code>null</code>)</span>
	 * <span class="zh-CN">新数组（如果两个给定数组均为 <code>null</code>，则为 <code>null</code>）</span>
	 */
	public static String[] mergeStringArrays(final String[] array1, final String... array2) {
		if (array1 == null) {
			return array2;
		}
		if (array2 == null) {
			return array1;
		}
		if (CollectionUtils.isEmpty(array1) && CollectionUtils.isEmpty(array2)) {
			return new String[0];
		}
		List<String> result = new ArrayList<>(Arrays.asList(array1));
		for (String str : array2) {
			if (!result.contains(str)) {
				result.add(str);
			}
		}
		return toStringArray(result);
	}

	/**
	 * <h3 class="en-US">Turn given sources String arrays into sorted arrays.</h3>
	 * <h3 class="zh-CN">将给定的源字符串数组转换为排序数组。</h3>
	 *
	 * @param array <span class="en-US">the source array</span>
	 *              <span class="zh-CN">源数组</span>
	 * @return <span class="en-US">the sorted array (never <code>null</code>)</span>
	 * <span class="zh-CN">排序后的数组（不会为<code>null</code>）</span>
	 */
	public static String[] sortStringArray(final String[] array) {
		if (CollectionUtils.isEmpty(array)) {
			return new String[0];
		}
		Arrays.sort(array);
		return array;
	}

	/**
	 * <h3 class="en-US">Copy the given Collection into a String array. The Collection must contain String elements only.</h3>
	 * <h3 class="zh-CN">将给定的集合复制到 String 数组中。集合必须仅包含字符串元素。</h3>
	 *
	 * @param collection <span class="en-US">the collection to copy</span>
	 *                   <span class="zh-CN">要复制的集合</span>
	 * @return <span class="en-US">the String array (<code>null</code> if the passed-in collection was <code>null</code>)</span>
	 * <span class="zh-CN">字符串数组（如果传入的集合为 <code>null</code>，则为 <code>null</code>）</span>
	 */
	public static String[] toStringArray(final Collection<String> collection) {
		if (collection == null) {
			return new String[0];
		}
		return collection.toArray(new String[0]);
	}

	/**
	 * <h3 class="en-US">Copy the given enumeration into a String array. The enumeration must contain String elements only.</h3>
	 * <h3 class="zh-CN">将给定的枚举复制到字符串数组中。枚举必须仅包含 String 元素。</h3>
	 *
	 * @param enumeration <span class="en-US">the enumeration to copy</span>
	 *                    <span class="zh-CN">要复制的枚举</span>
	 * @return <span class="en-US">the String array (<code>null</code> if the passed-in enumeration was <code>null</code>)</span>
	 * <span class="zh-CN">字符串数组（如果传入的枚举为 <code>null</code>，则为 <code>null</code>）</span>
	 */
	public static String[] toStringArray(final Enumeration<String> enumeration) {
		if (enumeration == null) {
			return new String[0];
		}
		List<String> list = Collections.list(enumeration);
		return list.toArray(new String[0]);
	}

	/**
	 * <h3 class="en-US">Trim the elements of the given string array, calling <code>String.trim()</code> on each of them.</h3>
	 * <h3 class="zh-CN">修剪给定字符串数组的元素，对每个元素调用 <code>String.trim()</code>。</h3>
	 *
	 * @param array <span class="en-US">the original String array</span>
	 *              <span class="zh-CN">原始字符串数组</span>
	 * @return <span class="en-US">the resulting array (of the same size) with trimmed elements</span>
	 * <span class="zh-CN">带有修剪元素的结果数组（相同大小）</span>
	 */
	public static String[] trimArrayElements(final String[] array) {
		if (CollectionUtils.isEmpty(array)) {
			return new String[0];
		}
		String[] result = new String[array.length];
		for (int i = 0; i < array.length; i++) {
			String element = array[i];
			result[i] = (element != null ? element.trim() : null);
		}
		return result;
	}

	/**
	 * <h3 class="en-US">Remove duplicate Strings from the given array. Also sorts the array, as it uses a TreeSet.</h3>
	 * <h3 class="zh-CN">从给定数组中删除重复的字符串。同时对数组进行排序，类似使用 TreeSet。</h3>
	 *
	 * @param array <span class="en-US">the String array</span>
	 *              <span class="zh-CN">字符串数组</span>
	 * @return <span class="en-US">an array without duplicates, in natural sort order</span>
	 * <span class="zh-CN">没有重复项的数组，按自然排序顺序</span>
	 */
	public static String[] removeDuplicateStrings(final String[] array) {
		if (CollectionUtils.isEmpty(array)) {
			return array;
		}
		Set<String> set = new TreeSet<>();
		Collections.addAll(set, array);
		return toStringArray(set);
	}

	/**
	 * <h3 class="en-US">Split a String at the first occurrence of the delimiter. Does not include the delimiter in the result.</h3>
	 * <h3 class="zh-CN">在第一次出现分隔符时分割字符串。结果中不包含分隔符。</h3>
	 *
	 * @param toSplit   <span class="en-US">the string to split</span>
	 *                  <span class="zh-CN">要分割的字符串</span>
	 * @param delimiter <span class="en-US">to split the string up with</span>
	 *                  <span class="zh-CN">分割字符串</span>
	 * @return <span class="en-US">
	 * a two element array with index 0 being before the delimiter,
	 * and index 1 being after the delimiter (neither element includes the delimiter);
	 * or <code>null</code> if the delimiter wasn't found in the given input String
	 * </span>
	 * <span class="zh-CN">
	 * 一个二元素数组，索引 0 位于分隔符之前，索引 1 位于分隔符之后（两个元素都不包含分隔符）；
	 * 或 <code>null</code> 如果在给定的输入字符串中找不到分隔符
	 * </span>
	 */
	public static String[] split(final String toSplit, final String delimiter) {
		if (hasLength(toSplit) || hasLength(delimiter)) {
			return null;
		}
		int offset = toSplit.indexOf(delimiter);
		if (offset < 0) {
			return new String[]{toSplit};
		}
		String beforeDelimiter = toSplit.substring(0, offset);
		String afterDelimiter = toSplit.substring(offset + delimiter.length());
		return new String[]{beforeDelimiter, afterDelimiter};
	}

	/**
	 * <h3 class="en-US">Take an array Strings and split each element based on the given delimiter.</h3>
	 * <span class="en-US">
	 * A <code>Properties</code> instance is then generated, with the left of the
	 * delimiter providing the key, and the right of the delimiter providing the value.
	 * Will trim both the key and value before adding them to the <code>Properties</code> instance.
	 * </span>
	 * <h3 class="zh-CN">获取一个字符串数组并根据给定的分隔符分割每个元素。</h3>
	 * <span class="zh-CN">
	 * 生成一个<code>Properties</code>实例对象，键值为分隔符前方的内容，属性值为分隔符后方的内容。
	 * 键值和属性值字符串在添加到<code>Properties</code>对象前执行修剪操作。
	 * </span>
	 *
	 * @param array     <span class="en-US">the array to process</span>
	 *                  <span class="zh-CN">要处理的数组</span>
	 * @param delimiter <span class="en-US">to split each element using (typically the equals symbol)</span>
	 *                  <span class="zh-CN">使用分隔符分割每个元素（通常是等于符号）</span>
	 * @return <span class="en-US">
	 * a <code>Properties</code> instance representing the array contents,
	 * or <code>null</code> if the array to process was null or empty.
	 * </span>
	 * <span class="zh-CN">表示数组内容的 <code>Properties</code> 实例，如果要处理的数组为 null 或空，则为 <code>null</code> 。</span>
	 */
	public static Properties splitArrayElementsIntoProperties(final String[] array, final String delimiter) {
		return splitArrayElementsIntoProperties(array, delimiter, null);
	}

	/**
	 * <h3 class="en-US">Take an array Strings and split each element based on the given delimiter.</h3>
	 * <span class="en-US">
	 * A <code>Properties</code> instance is then generated, with the left of the
	 * delimiter providing the key, and the right of the delimiter providing the value.
	 * Will trim both the key and value before adding them to the <code>Properties</code> instance.
	 * </span>
	 * <h3 class="zh-CN">获取一个字符串数组并根据给定的分隔符分割每个元素。</h3>
	 * <span class="zh-CN">
	 * 生成一个<code>Properties</code>实例对象，键值为分隔符前方的内容，属性值为分隔符后方的内容。
	 * 键值和属性值字符串在添加到<code>Properties</code>对象前执行修剪操作。
	 * </span>
	 *
	 * @param array         <span class="en-US">the array to process</span>
	 *                      <span class="zh-CN">要处理的数组</span>
	 * @param delimiter     <span class="en-US">to split each element using (typically the equals symbol)</span>
	 *                      <span class="zh-CN">使用分隔符分割每个元素（通常是等于符号）</span>
	 * @param charsToDelete <span class="en-US">
	 *                      one or more characters to remove from each element prior to attempting
	 *                      the split operation (typically the quotation mark symbol),
	 *                      or <code>null</code> if no removal should occur
	 *                      </span>
	 *                      <span class="zh-CN">
	 *                      在尝试拆分操作之前要从每个元素中删除的一个或多个字符（通常是引号符号），如果不应该删除，则为 <code>null</code>
	 *                      </span>
	 * @return <span class="en-US">
	 * a <code>Properties</code> instance representing the array contents,
	 * or <code>null</code> if the array to process was null or empty.
	 * </span>
	 * <span class="zh-CN">表示数组内容的 <code>Properties</code> 实例，如果要处理的数组为 null 或空，则为 <code>null</code> 。</span>
	 */
	public static Properties splitArrayElementsIntoProperties(final String[] array, final String delimiter,
	                                                          final String charsToDelete) {

		if (CollectionUtils.isEmpty(array)) {
			return null;
		}
		Properties result = new Properties();
		for (String string : array) {
			String element = string;
			if (charsToDelete != null) {
				element = deleteAny(string, charsToDelete);
			}
			String[] splitterElement = split(element, delimiter);
			if (splitterElement == null) {
				continue;
			}
			result.setProperty(splitterElement[0].trim(), splitterElement[1].trim());
		}
		return result;
	}

	/**
	 * <h3 class="en-US">Tokenize the given String into a String array via a StringTokenizer.</h3>
	 * <span class="en-US">
	 * Trims tokens and omits empty tokens.
	 * The given delimiters string is supposed to consist of any number of
	 * delimiter characters. Each of those characters can be used to separate
	 * tokens. A delimiter is always a single character; for multi-character
	 * delimiters, consider using <code>delimitedListToStringArray</code>
	 * </span>
	 * <h3 class="zh-CN">通过 StringTokenizer 将给定的字符串标记为字符串数组。</h3>
	 * <span class="zh-CN">
	 * 修剪标记并省略空标记。给定的分隔符字符串应该由任意数量的分隔符字符组成。这些字符中的每一个都可以用于分隔标记。
	 * 分隔符始终是单个字符；对于多字符分隔符，请考虑使用 <code>delimitedListToStringArray</code>
	 * </span>
	 *
	 * @param str        <span class="en-US">the String to tokenize</span>
	 *                   <span class="zh-CN">要处理的字符串</span>
	 * @param delimiters <span class="en-US">the delimiter characters, assembled as String (each of those characters is individually considered as delimiter).</span>
	 *                   <span class="zh-CN">分隔符字符，组装为字符串（每个字符都被单独视为分隔符）。</span>
	 * @return <span class="en-US">an array of the tokens (<code>null</code> if the input String was <code>null</code>)</span>
	 * <span class="zh-CN">处理后的字符串数组（如果输入字符串为 <code>null</code>，则为 <code>null</code>）</span>
	 * @see java.util.StringTokenizer
	 * @see java.lang.String#trim() java.lang.String#trim()
	 * @see StringUtils#tokenizeToStringArray(String, String, boolean, boolean)
	 */
	public static String[] tokenizeToStringArray(final String str, final String delimiters) {
		return tokenizeToStringArray(str, delimiters, Boolean.TRUE, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Tokenize the given String into a String array via a StringTokenizer.</h3>
	 * <span class="en-US">
	 * The given delimiters string is supposed to consist of any number of
	 * delimiter characters. Each of those characters can be used to separate
	 * tokens. A delimiter is always a single character; for multi-character
	 * delimiters, consider using <code>delimitedListToStringArray</code>
	 * </span>
	 * <h3 class="zh-CN">通过 StringTokenizer 将给定的字符串标记为字符串数组。</h3>
	 * <span class="zh-CN">
	 * 给定的分隔符字符串应该由任意数量的分隔符字符组成。这些字符中的每一个都可以用于分隔标记。
	 * 分隔符始终是单个字符；对于多字符分隔符，请考虑使用 <code>delimitedListToStringArray</code>
	 * </span>
	 *
	 * @param str               <span class="en-US">the String to tokenize</span>
	 *                          <span class="zh-CN">要处理的字符串</span>
	 * @param delimiters        <span class="en-US">
	 *                          the delimiter characters, assembled as String (each of those characters
	 *                          is individually considered as delimiter).
	 *                          </span>
	 *                          <span class="zh-CN">分隔符字符，组装为字符串（每个字符都被单独视为分隔符）。</span>
	 * @param trimTokens        <span class="en-US">trim the tokens via String's <code>trim</code></span>
	 *                          <span class="zh-CN">通过 String 的 <code>trim</code> 修剪标记</span>
	 * @param ignoreEmptyTokens <span class="en-US">
	 *                          omit empty tokens from the result array (only applies to tokens that are empty
	 *                          after trimming; StringTokenizer will not consider subsequent delimiters
	 *                          as token in the first place).
	 *                          </span>
	 *                          <span class="zh-CN">
	 *                          从结果数组中省略空标记（仅适用于修剪后为空的标记；StringTokenizer 首先不会将后续分隔符视为标记）。
	 *                          </span>
	 * @return <span class="en-US">an array of the tokens (<code>null</code> if the input String was <code>null</code>)</span>
	 * <span class="zh-CN">处理后的字符串数组（如果输入字符串为 <code>null</code>，则为 <code>null</code>）</span>
	 * @see java.util.StringTokenizer
	 * @see java.lang.String#trim() java.lang.String#trim()
	 * @see StringUtils#delimitedListToStringArray
	 */
	public static String[] tokenizeToStringArray(final String str, final String delimiters, final boolean trimTokens,
	                                             final boolean ignoreEmptyTokens) {

		if (str == null) {
			return null;
		}
		StringTokenizer st = new StringTokenizer(str, delimiters);
		List<String> tokens = new ArrayList<>();
		while (st.hasMoreTokens()) {
			String token = st.nextToken();
			if (trimTokens) {
				token = token.trim();
			}
			if (!ignoreEmptyTokens || !token.isEmpty()) {
				tokens.add(token);
			}
		}
		return toStringArray(tokens);
	}

	/**
	 * <h3 class="en-US">Take a String which is a delimited list and convert it to a String array.</h3>
	 * <span class="en-US">
	 * A single delimiter can consist of more than one character: It will still
	 * be considered as single delimiter string, rather than as a bunch of potential
	 * delimiter characters - in contrast to <code>tokenizeToStringArray</code>.
	 * </span>
	 * <h3 class="zh-CN">获取一个分隔列表的字符串并将其转换为字符串数组。</h3>
	 * <span class="zh-CN">
	 * 单个分隔符可以包含多个字符：它仍将被视为单个分隔符字符串，
	 * 而不是一堆潜在的分隔符 - 与 <code>tokenizeToStringArray</code> 不同。
	 * </span>
	 *
	 * @param str       <span class="en-US">the input String</span>
	 *                  <span class="zh-CN">输入字符串</span>
	 * @param delimiter <span class="en-US">
	 *                  the delimiter between elements (this is a single delimiter,
	 *                  rather than a bunch individual delimiter characters)
	 *                  </span>
	 *                  <span class="zh-CN">元素之间的分隔符（这是单个分隔符，而不是一堆单独的分隔符）</span>
	 * @return <span class="en-US">an array of the tokens in the list</span>
	 * <span class="zh-CN">列表中标记的数组</span>
	 */
	public static String[] delimitedListToStringArray(final String str, final String delimiter) {
		return delimitedListToStringArray(str, delimiter, null);
	}

	/**
	 * <h3 class="en-US">Take a String which is a delimited list and convert it to a String array.</h3>
	 * <span class="en-US">
	 * A single delimiter can consist of more than one character: It will still
	 * be considered as single delimiter string, rather than as a bunch of potential
	 * delimiter characters - in contrast to <code>tokenizeToStringArray</code>.
	 * </span>
	 * <h3 class="zh-CN">获取一个分隔列表的字符串并将其转换为字符串数组。</h3>
	 * <span class="zh-CN">
	 * 单个分隔符可以包含多个字符：它仍将被视为单个分隔符字符串，
	 * 而不是一堆潜在的分隔符 - 与 <code>tokenizeToStringArray</code> 不同。
	 * </span>
	 *
	 * @param str           <span class="en-US">the input String</span>
	 *                      <span class="zh-CN">输入字符串</span>
	 * @param delimiter     <span class="en-US">
	 *                      the delimiter between elements (this is a single delimiter,
	 *                      rather than a bunch individual delimiter characters)
	 *                      </span>
	 *                      <span class="zh-CN">元素之间的分隔符（这是单个分隔符，而不是一堆单独的分隔符）</span>
	 * @param charsToDelete <span class="en-US">
	 *                      a set of characters to delete. Useful for deleting unwanted line breaks:
	 *                      e.g. "\r\n\f" will delete all new lines, line feeds in a String.
	 *                      </span>
	 *                      <span class="zh-CN">
	 *                      要删除的一组字符。对于删除不需要的换行符很有用：例如“\r\n\f” 将删除字符串中的所有新行、换行符。
	 *                      </span>
	 * @return <span class="en-US">an array of the tokens in the list</span>
	 * <span class="zh-CN">列表中标记的数组</span>
	 */
	public static String[] delimitedListToStringArray(final String str, final String delimiter,
	                                                  final String charsToDelete) {
		if (str == null) {
			return new String[0];
		}
		if (delimiter == null) {
			return new String[]{str};
		}
		List<String> result = new ArrayList<>();
		if (Globals.DEFAULT_VALUE_STRING.equals(delimiter)) {
			for (int i = 0; i < str.length(); i++) {
				result.add(deleteAny(str.substring(i, i + 1), charsToDelete));
			}
		} else {
			int pos = 0;
			int delPos;
			while ((delPos = str.indexOf(delimiter, pos)) != -1) {
				result.add(deleteAny(str.substring(pos, delPos), charsToDelete));
				pos = delPos + delimiter.length();
			}
			if (!str.isEmpty() && pos <= str.length()) {
				// Add rest of String, but not in case of empty input.
				result.add(deleteAny(str.substring(pos), charsToDelete));
			}
		}
		return toStringArray(result);
	}

	/**
	 * <h3 class="en-US">Convert a CSV list into an array of Strings.</h3>
	 * <h3 class="zh-CN">将 CSV 列表转换为字符串数组。</h3>
	 *
	 * @param str <span class="en-US">the input String</span>
	 *            <span class="zh-CN">输入字符串</span>
	 * @return <span class="en-US">an array of Strings, or the empty array in case of empty input</span>
	 * <span class="zh-CN">字符串数组，或者空数组（如果输入为空）</span>
	 */
	public static String[] commaDelimitedListToStringArray(final String str) {
		return delimitedListToStringArray(str, ",");
	}

	/**
	 * <h3 class="en-US">Convert a CSV list into an array of Strings. Note that this will suppress duplicates.</h3>
	 * <h3 class="zh-CN">将 CSV 列表转换为字符串数组。请注意，此操作将移除重复项。</h3>
	 *
	 * @param str <span class="en-US">the input String</span>
	 *            <span class="zh-CN">输入字符串</span>
	 * @return <span class="en-US">an array of Strings, or the empty array in case of empty input</span>
	 * <span class="zh-CN">字符串数组，或者空数组（如果输入为空）</span>
	 */
	public static Set<String> commaDelimitedListToSet(final String str) {
		Set<String> set = new TreeSet<>();
		String[] tokens = commaDelimitedListToStringArray(str);
		Collections.addAll(set, tokens);
		return set;
	}

	/**
	 * <h3 class="en-US">Convenience method to return a Collection as a delimited (e.g. CSV) String. E.g., useful for <code>toString()</code> implementations.</h3>
	 * <h3 class="zh-CN">将集合用分隔连接（例如 CSV）字符串返回的便捷方法。例如。常用于 <code>toString()</code> 实现。</h3>
	 *
	 * @param coll <span class="en-US">the Collection to display</span>
	 *             <span class="zh-CN">要显示的集合</span>
	 * @return <span class="en-US">the delimited String</span>
	 * <span class="zh-CN">拼接后的字符串</span>
	 */
	public static String collectionToCommaDelimitedString(final Collection<String> coll) {
		return collectionToDelimitedString(coll, ",");
	}

	/**
	 * <h3 class="en-US">Convenience method to return a Collection as a delimited (e.g. CSV) String. E.g., useful for <code>toString()</code> implementations.</h3>
	 * <h3 class="zh-CN">将集合用分隔连接（例如 CSV）字符串返回的便捷方法。例如。常用于 <code>toString()</code> 实现。</h3>
	 *
	 * @param coll      <span class="en-US">the Collection to display</span>
	 *                  <span class="zh-CN">要显示的集合</span>
	 * @param delimiter <span class="en-US">the delimiter to use (probably a ",")</span>
	 *                  <span class="zh-CN">要使用的分隔符（常见为 “,”）</span>
	 * @return <span class="en-US">the delimited String</span>
	 * <span class="zh-CN">拼接后的字符串</span>
	 */
	public static String collectionToDelimitedString(final Collection<String> coll, final String delimiter) {
		return collectionToDelimitedString(coll, delimiter, Globals.DEFAULT_VALUE_STRING, Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * <h3 class="en-US">Convenience method to return a Collection as a delimited (e.g. CSV) String. E.g., useful for <code>toString()</code> implementations.</h3>
	 * <h3 class="zh-CN">将集合用分隔连接（例如 CSV）字符串返回的便捷方法。例如。常用于 <code>toString()</code> 实现。</h3>
	 *
	 * @param coll      <span class="en-US">the Collection to display</span>
	 *                  <span class="zh-CN">要显示的集合</span>
	 * @param delimiter <span class="en-US">the delimiter to use (probably a ",")</span>
	 *                  <span class="zh-CN">要使用的分隔符（常见为 “,”）</span>
	 * @param prefix    <span class="en-US">the String to start each element with</span>
	 *                  <span class="zh-CN">每个元素的开头字符串</span>
	 * @param suffix    <span class="en-US">the String to end each element with</span>
	 *                  <span class="zh-CN">每个元素的结尾字符串</span>
	 * @return <span class="en-US">the delimited String</span>
	 * <span class="zh-CN">拼接后的字符串</span>
	 */
	public static String collectionToDelimitedString(final Collection<String> coll, final String delimiter,
	                                                 final String prefix, final String suffix) {
		if (CollectionUtils.isEmpty(coll)) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		StringBuilder sb = new StringBuilder();
		Iterator<String> it = coll.iterator();
		while (it.hasNext()) {
			sb.append(prefix).append(it.next()).append(suffix);
			if (it.hasNext()) {
				sb.append(delimiter);
			}
		}
		return sb.toString();
	}

	/**
	 * <h3 class="en-US">Check the given string contains search string, ignore case</h3>
	 * <h3 class="zh-CN">检查给定的字符串是否包含搜索字符串，忽略大小写</h3>
	 *
	 * @param string <span class="en-US">The given string</span>
	 *               <span class="zh-CN">给定的字符串</span>
	 * @param search <span class="en-US">the search string</span>
	 *               <span class="zh-CN">搜索字符串</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean containsIgnoreCase(final String string, final String search) {
		if (string == null || search == null) {
			return false;
		}
		int length = search.length();
		int maxLength = string.length() - length;
		for (int i = 0; i < maxLength; i++) {
			if (string.regionMatches(Boolean.TRUE, i, search, Globals.INITIALIZE_INT_VALUE, length)) {
				return Boolean.TRUE;
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Convenience method to return an Object array as a delimited (e.g. CSV) String. E.g., useful for <code>toString()</code> implementations.</h3>
	 * <h3 class="zh-CN">将对象数组用分隔连接（例如 CSV）字符串返回的便捷方法。例如。常用于 <code>toString()</code> 实现。</h3>
	 *
	 * @param arr <span class="en-US">the String array to display</span>
	 *            <span class="zh-CN">要显示的对象数组</span>
	 * @return <span class="en-US">the delimited String</span>
	 * <span class="zh-CN">拼接后的字符串</span>
	 */
	public static String arrayToCommaDelimitedString(final Object[] arr) {
		return arrayToDelimitedString(arr, ",");
	}

	/**
	 * <h3 class="en-US">Convenience method to return an Object array as a delimited (e.g. CSV) String. E.g., useful for <code>toString()</code> implementations.</h3>
	 * <h3 class="zh-CN">将对象数组用分隔连接（例如 CSV）字符串返回的便捷方法。例如。常用于 <code>toString()</code> 实现。</h3>
	 *
	 * @param arr       <span class="en-US">the String array to display</span>
	 *                  <span class="zh-CN">要显示的对象数组</span>
	 * @param delimiter <span class="en-US">the delimiter to use (probably a ",")</span>
	 *                  <span class="zh-CN">要使用的分隔符（常见为 “,”）</span>
	 * @return <span class="en-US">the delimited String</span>
	 * <span class="zh-CN">拼接后的字符串</span>
	 */
	public static String arrayToDelimitedString(final Object[] arr, final String delimiter) {
		if (CollectionUtils.isEmpty(arr)) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < arr.length; i++) {
			if (i > 0) {
				sb.append(delimiter);
			}
			sb.append(arr[i]);
		}
		return sb.toString();
	}

	/**
	 * <h3 class="en-US">Convenience method to return a JavaBean object as a string. </h3>
	 * <h3 class="zh-CN">将JavaBean实例对象转换为字符串</h3>
	 *
	 * @param object       <span class="en-US">JavaBean object</span>
	 *                     <span class="zh-CN">JavaBean实例对象</span>
	 * @param stringType   <span class="en-US">Target string type</span>
	 *                     <span class="zh-CN">目标字符串类型</span>
	 * @param formatOutput <span class="en-US">format output string</span>
	 *                     <span class="zh-CN">格式化输出字符串</span>
	 * @return <span class="en-US">the converted string</span>
	 * <span class="zh-CN">转换后的字符串</span>
	 */
	public static String objectToString(final Object object, final StringType stringType, final boolean formatOutput) {
		return objectToString(object, stringType, formatOutput, Boolean.TRUE, Globals.DEFAULT_ENCODING);
	}

	/**
	 * <h3 class="en-US">Convenience method to return a JavaBean object as a string. </h3>
	 * <h3 class="zh-CN">将JavaBean实例对象转换为字符串</h3>
	 *
	 * @param object       <span class="en-US">JavaBean object</span>
	 *                     <span class="zh-CN">JavaBean实例对象</span>
	 * @param stringType   <span class="en-US">Target string type</span>
	 *                     <span class="zh-CN">目标字符串类型</span>
	 * @param formatOutput <span class="en-US">format output string</span>
	 *                     <span class="zh-CN">格式化输出字符串</span>
	 * @return <span class="en-US">the converted string</span>
	 * <span class="zh-CN">转换后的字符串</span>
	 */
	public static String objectToString(final Object object, final StringType stringType, final boolean formatOutput,
	                                    final boolean outputFragment, final String encoding) {
		ObjectMapper objectMapper;
		switch (stringType) {
			case XML:
				if (!object.getClass().isAnnotationPresent(XmlRootElement.class)) {
					return Globals.DEFAULT_VALUE_STRING;
				}
				StringWriter stringWriter = null;
				try {
					String characterEncoding = StringUtils.isEmpty(encoding) ? Globals.DEFAULT_ENCODING : encoding;
					stringWriter = new StringWriter();
					XMLStreamWriter xmlWriter = XMLOutputFactory.newInstance().createXMLStreamWriter(stringWriter);
					CDataStreamWriter streamWriter = new CDataStreamWriter(xmlWriter);

					JAXBContext jaxbContext = JAXBContext.newInstance(object.getClass());
					Marshaller marshaller = jaxbContext.createMarshaller();
					marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, formatOutput);
					marshaller.setProperty(Marshaller.JAXB_ENCODING, characterEncoding);
					marshaller.setProperty(Marshaller.JAXB_FRAGMENT, Boolean.TRUE);

					marshaller.marshal(object, streamWriter);

					streamWriter.flush();
					streamWriter.close();

					if (formatOutput) {
						Transformer transformer = TransformerFactory.newInstance().newTransformer();
						transformer.setOutputProperty(OutputKeys.ENCODING, characterEncoding);
						transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
						transformer.setOutputProperty(OutputKeys.INDENT, "yes");
						transformer.setOutputProperty("{https://xml.apache.org/xslt}indent-amount", "4");

						String xml = stringWriter.toString();
						stringWriter = new StringWriter();

						transformer.transform(new StreamSource(new StringReader(xml)), new StreamResult(stringWriter));
					}

					StringBuilder stringBuilder = new StringBuilder();
					if (outputFragment) {
						stringBuilder.append(StringUtils.replace(FRAGMENT_TEMPLATE, "{}", characterEncoding));
						if (formatOutput) {
							stringBuilder.append(FileUtils.LF);
						}
					}
					stringBuilder.append(stringWriter);
					return stringBuilder.toString();
				} catch (Exception e) {
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Stack_Message_Error", e);
					}
					return Globals.DEFAULT_VALUE_STRING;
				} finally {
					IOUtils.closeStream(stringWriter);
				}
			case JSON:
				objectMapper = new ObjectMapper().disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
				break;
			case YAML:
				objectMapper = new ObjectMapper(new YAMLFactory().disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER))
						.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
				break;
			case SERIALIZABLE:
				return StringUtils.base64Encode(ConvertUtils.toByteArray(object));
			default:
				return Globals.DEFAULT_VALUE_STRING;
		}
		try {
			return formatOutput
					? objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(object)
					: objectMapper.writeValueAsString(object);
		} catch (JsonProcessingException e) {
			LOGGER.error("Convert_String_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}
		return Globals.DEFAULT_VALUE_STRING;
	}

	/**
	 * <h3 class="en-US">Parse strings to target JavaBean instance. </h3>
	 * <h3 class="zh-CN">解析字符串为目标JavaBean实例对象</h3>
	 *
	 * @param <T>         <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param string      <span class="en-US">The string will parse</span>
	 *                    <span class="zh-CN">要解析的字符串</span>
	 * @param beanClass   <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param schemaPaths <span class="en-US">XML schema path(Maybe schema uri or local path)</span>
	 *                    <span class="zh-CN">XML描述文件路径（可能为描述文件URI或本地文件路径）</span>
	 * @return <span class="en-US">Converted object instance</span>
	 * <span class="zh-CN">转换后的实例对象</span>
	 */
	public static <T> T stringToObject(final String string, final Class<T> beanClass, final String... schemaPaths) {
		return stringToObject(string, Globals.DEFAULT_ENCODING, beanClass, schemaPaths);
	}

	/**
	 * <h3 class="en-US">Parse strings to target JavaBean instance. </h3>
	 * <h3 class="zh-CN">解析字符串为目标JavaBean实例对象</h3>
	 *
	 * @param <T>         <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param string      <span class="en-US">The string will parse</span>
	 *                    <span class="zh-CN">要解析的字符串</span>
	 * @param stringType  <span class="en-US">The string type</span>
	 *                    <span class="zh-CN">字符串类型</span>
	 * @param beanClass   <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param schemaPaths <span class="en-US">XML schema path(Maybe schema uri or local path)</span>
	 *                    <span class="zh-CN">XML描述文件路径（可能为描述文件URI或本地文件路径）</span>
	 * @return <span class="en-US">Converted object instance</span>
	 * <span class="zh-CN">转换后的实例对象</span>
	 */
	public static <T> T stringToObject(final String string, final StringType stringType, final Class<T> beanClass,
	                                   final String... schemaPaths) {
		return stringToObject(string, stringType, Globals.DEFAULT_ENCODING, beanClass, schemaPaths);
	}

	/**
	 * <h3 class="en-US">Parse strings to target JavaBean instance. </h3>
	 * <h3 class="zh-CN">解析字符串为目标JavaBean实例对象</h3>
	 *
	 * @param <T>         <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param string      <span class="en-US">The string will parse</span>
	 *                    <span class="zh-CN">要解析的字符串</span>
	 * @param encoding    <span class="en-US">String charset encoding</span>
	 *                    <span class="zh-CN">字符串的字符集编码</span>
	 * @param beanClass   <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param schemaPaths <span class="en-US">XML schema path(Maybe schema uri or local path)</span>
	 *                    <span class="zh-CN">XML描述文件路径（可能为描述文件URI或本地文件路径）</span>
	 * @return <span class="en-US">Converted object instance</span>
	 * <span class="zh-CN">转换后的实例对象</span>
	 */
	public static <T> T stringToObject(final String string, final String encoding,
	                                   final Class<T> beanClass, final String... schemaPaths) {
		if (StringUtils.isEmpty(string)) {
			LOGGER.error("Parse_Empty_String_Error");
			return null;
		}
		if (ClassUtils.isAssignable(Map.class, beanClass)) {
			return beanClass.cast(StringUtils.dataToMap(string, StringType.JSON));
		}
		switch (string.charAt(0)) {
			case '<':
				return stringToObject(string, StringType.XML, encoding, beanClass, schemaPaths);
			case '{':
				return stringToObject(string, StringType.JSON, encoding, beanClass, schemaPaths);
			default:
				return stringToObject(string,
						StringUtils.matches(string, RegexGlobals.BASE64) ? StringType.SERIALIZABLE : StringType.YAML,
						encoding, beanClass, schemaPaths);
		}
	}

	/**
	 * <h3 class="en-US">Parse strings to target JavaBean instance list. </h3>
	 * <h3 class="zh-CN">解析字符串为目标JavaBean实例对象列表</h3>
	 *
	 * @param <T>       <span class="en-US">target JavaBean class</span>
	 *                  <span class="zh-CN">目标JavaBean类</span>
	 * @param string    <span class="en-US">The string will parse</span>
	 *                  <span class="zh-CN">要解析的字符串</span>
	 * @param encoding  <span class="en-US">String charset encoding</span>
	 *                  <span class="zh-CN">字符串的字符集编码</span>
	 * @param beanClass <span class="en-US">target JavaBean class</span>
	 *                  <span class="zh-CN">目标JavaBean类</span>
	 * @return <span class="en-US">Converted object instance list</span>
	 * <span class="zh-CN">转换后的实例对象列表</span>
	 */
	public static <T> List<T> stringToList(final String string, final String encoding, final Class<T> beanClass) {
		if (StringUtils.isEmpty(string)) {
			LOGGER.error("Parse_Empty_String_Error");
			return null;
		}

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Parse_String_Debug", string, encoding, beanClass.getName());
		}

		String stringEncoding = (encoding == null) ? Globals.DEFAULT_ENCODING : encoding;
		try (InputStream inputStream = new ByteArrayInputStream(string.getBytes(stringEncoding))) {
			return streamToList(inputStream, beanClass);
		} catch (IOException e) {
			LOGGER.error("Parse_String_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return new ArrayList<>();
		}
	}

	/**
	 * <h3 class="en-US">Parse file content to target JavaBean instance list. </h3>
	 * <h3 class="zh-CN">解析文件内容为目标JavaBean实例对象列表</h3>
	 *
	 * @param <T>         <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param filePath    <span class="en-US">File path</span>
	 *                    <span class="zh-CN">文件地址</span>
	 * @param beanClass   <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param schemaPaths <span class="en-US">XML schema path(Maybe schema uri or local path)</span>
	 *                    <span class="zh-CN">XML描述文件路径（可能为描述文件URI或本地文件路径）</span>
	 * @return <span class="en-US">Converted object instance</span>
	 * <span class="zh-CN">转换后的实例对象</span>
	 */
	public static <T> T fileToObject(final String filePath, final Class<T> beanClass, final String... schemaPaths) {
		if (StringUtils.isEmpty(filePath) || !FileUtils.isExists(filePath)) {
			LOGGER.error("Not_Found_File_Error", filePath);
			return null;
		}
		String extName = StringUtils.getFilenameExtension(filePath);
		try (InputStream inputStream = FileUtils.loadFile(filePath)) {
			switch (extName.toLowerCase()) {
				case "json":
					return streamToObject(inputStream, StringType.JSON, beanClass, Globals.DEFAULT_VALUE_STRING);
				case "xml":
					return streamToObject(inputStream, StringType.XML, beanClass, schemaPaths);
				case "yml":
				case "yaml":
					return streamToObject(inputStream, StringType.YAML, beanClass, Globals.DEFAULT_VALUE_STRING);
				default:
					return streamToObject(inputStream, StringType.SERIALIZABLE, beanClass, Globals.DEFAULT_VALUE_STRING);
			}
		} catch (IOException e) {
			LOGGER.error("Parse_File_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Parse the content of input stream to target JavaBean instance list. </h3>
	 * <h3 class="zh-CN">解析输入流中的内容为目标JavaBean实例对象列表</h3>
	 *
	 * @param <T>         <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param inputStream <span class="en-US">Input stream instance</span>
	 *                    <span class="zh-CN">输入流对象实例</span>
	 * @param beanClass   <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @return <span class="en-US">Converted object instance list</span>
	 * <span class="zh-CN">转换后的实例对象列表</span>
	 * @throws IOException the io exception
	 *                     <span class="en-US">If an error occurs when read data from input stream</span>
	 *                     <span class="zh-CN">如果从输入流中读取数据时出现异常</span>
	 */
	public static <T> List<T> streamToList(final InputStream inputStream, final Class<T> beanClass) throws IOException {
		ObjectMapper objectMapper = new ObjectMapper();
		JavaType javaType = objectMapper.getTypeFactory().constructParametricType(ArrayList.class, beanClass);
		return objectMapper.readValue(inputStream, javaType);
	}

	/**
	 * <h3 class="en-US">Verify that the given XML data conforms to the format of the given XML description file.</h3>
	 * <h3 class="zh-CN">验证给定的XML数据是否符合给定的XML描述文件的格式</h3>
	 *
	 * @param xmlData     <span class="en-US">Given XML data</span>
	 *                    <span class="zh-CN">给定的XML数据</span>
	 * @param schemaPaths <span class="en-US">XML schema path(Maybe schema uri or local path)</span>
	 *                    <span class="zh-CN">XML描述文件路径（可能为描述文件URI或本地文件路径）</span>
	 * @return <span class="en-US">Verify result</span>
	 * <span class="zh-CN">验证结果</span>
	 */
	public static boolean validate(final String xmlData, final String... schemaPaths) {
		return Optional.ofNullable(newSchema(schemaPaths))
				.map(schema -> {
					try {
						DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
						documentBuilderFactory.setNamespaceAware(Boolean.TRUE);
						DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
						Document document = documentBuilder.parse(new InputSource(new StringReader(xmlData)));
						schema.newValidator().validate(new DOMSource(document));
						return Boolean.TRUE;
					} catch (ParserConfigurationException | SAXException | IOException e) {
						return Boolean.FALSE;
					}
				})
				.orElse(Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Parse the content of input stream to target JavaBean instance list. </h3>
	 * <h3 class="zh-CN">解析输入流中的内容为目标JavaBean实例对象列表</h3>
	 *
	 * @param <T>         <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param inputStream <span class="en-US">Input stream instance</span>
	 *                    <span class="zh-CN">输入流对象实例</span>
	 * @param beanClass   <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param schemaPaths <span class="en-US">XML schema path(Maybe schema uri or local path)</span>
	 *                    <span class="zh-CN">XML描述文件路径（可能为描述文件URI或本地文件路径）</span>
	 * @return <span class="en-US">Converted object instance list</span>
	 * <span class="zh-CN">转换后的实例对象列表</span>
	 * @throws IOException the io exception
	 *                     <span class="en-US">If an error occurs when read data from input stream</span>
	 *                     <span class="zh-CN">如果从输入流中读取数据时出现异常</span>
	 */
	public static <T> T streamToObject(final InputStream inputStream, final Class<T> beanClass,
	                                   final String... schemaPaths) throws IOException {
		OutputConfig outputConfig = beanClass.getAnnotation(OutputConfig.class);
		if (outputConfig == null) {
			return streamToObject(inputStream, StringType.SERIALIZABLE, beanClass, schemaPaths);
		}
		return streamToObject(inputStream, outputConfig.type(), beanClass, schemaPaths);
	}

	/**
	 * <h3 class="en-US">Parse the content of input stream to target JavaBean instance list. </h3>
	 * <h3 class="zh-CN">解析输入流中的内容为目标JavaBean实例对象列表</h3>
	 *
	 * @param <T>         <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param inputStream <span class="en-US">Input stream instance</span>
	 *                    <span class="zh-CN">输入流对象实例</span>
	 * @param stringType  <span class="en-US">The string type</span>
	 *                    <span class="zh-CN">字符串类型</span>
	 * @param beanClass   <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param schemaPaths <span class="en-US">XML schema path(Maybe schema uri or local path)</span>
	 *                    <span class="zh-CN">XML描述文件路径（可能为描述文件URI或本地文件路径）</span>
	 * @return <span class="en-US">Converted object instance list</span>
	 * <span class="zh-CN">转换后的实例对象列表</span>
	 * @throws IOException the io exception
	 *                     <span class="en-US">If an error occurs when read data from input stream</span>
	 *                     <span class="zh-CN">如果从输入流中读取数据时出现异常</span>
	 */
	public static <T> T streamToObject(final InputStream inputStream, final StringType stringType,
	                                   final Class<T> beanClass, final String... schemaPaths) throws IOException {
		switch (stringType) {
			case XML:
				try {
					Unmarshaller unmarshaller = JAXBContext.newInstance(beanClass).createUnmarshaller();
					Optional.ofNullable(newSchema(schemaPaths))
							.ifPresent(unmarshaller::setSchema);
					return beanClass.cast(unmarshaller.unmarshal(inputStream));
				} catch (JAXBException e) {
					LOGGER.error("Parse_File_Error");
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Stack_Message_Error", e);
					}
					return null;
				}
			case SIMPLE:
				return ClassUtils.parseSimpleData(IOUtils.readContent(inputStream), beanClass);
			case SERIALIZABLE:
				return Optional.of(IOUtils.readContent(inputStream))
						.map(StringUtils::base64Decode)
						.map(ConvertUtils::toObject)
						.filter(object -> ClassUtils.isAssignable(object.getClass(), beanClass))
						.map(beanClass::cast)
						.orElse(null);
			case JSON:
				return new ObjectMapper().disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
						.readValue(IOUtils.readContent(inputStream), beanClass);
			case YAML:
				return new ObjectMapper(new YAMLFactory().disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER))
						.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
						.readValue(IOUtils.readContent(inputStream), beanClass);
			default:
				return null;
		}
	}

	/**
	 * <h3 class="en-US">Parse string to data map.</h3>
	 * <h3 class="zh-CN">解析字符串为数据映射表</h3>
	 *
	 * @param string     <span class="en-US">The string will parse</span>
	 *                   <span class="zh-CN">要解析的字符串</span>
	 * @param stringType <span class="en-US">The string type</span>
	 *                   <span class="zh-CN">字符串类型</span>
	 * @return <span class="en-US">Converted data map</span>
	 * <span class="zh-CN">转换后的数据映射表</span>
	 */
	public static Map<String, Object> dataToMap(final String string, final StringType stringType) {
		ObjectMapper objectMapper;
		switch (stringType) {
			case JSON:
				objectMapper = new ObjectMapper().disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
				break;
			case YAML:
				objectMapper = new ObjectMapper(new YAMLFactory().disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER))
						.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
				break;
			default:
				return new HashMap<>();
		}
		try {
			return objectMapper.readValue(string, new TypeReference<>() {
			});
		} catch (Exception e) {
			LOGGER.error("Convert_To_Data_Map_Error");
			if (StringUtils.LOGGER.isDebugEnabled()) {
				StringUtils.LOGGER.debug("Stack_Message_Error", e);
			}
		}

		return new HashMap<>();
	}

	/**
	 * <h3 class="en-US">Replace converted character with special XML character in string.</h3>
	 * <h3 class="zh-CN">替换转义字符串为XML特殊字符</h3>
	 *
	 * @param sourceString <span class="en-US">The string will process</span>
	 *                     <span class="zh-CN">要处理的字符串</span>
	 * @return <span class="en-US">Replaced string</span>
	 * <span class="zh-CN">替换后的字符串</span>
	 */
	public static String formatForText(final String sourceString) {

		if (StringUtils.isEmpty(sourceString)) {
			return sourceString;
		}

		String replaceString = replace(sourceString, "&amp;", "&");
		replaceString = replace(replaceString, "&lt;", "<");
		replaceString = replace(replaceString, "&gt;", ">");
		replaceString = replace(replaceString, "&quot;", "\"");
		replaceString = replace(replaceString, "&#39;", "'");
		replaceString = replace(replaceString, "\\\\", "\\");
		replaceString = replace(replaceString, "\\n", Character.toString(FileUtils.LF));
		replaceString = replace(replaceString, "\\r", Character.toString(FileUtils.CR));
		replaceString = replace(replaceString, "<br/>", Character.toString(FileUtils.CR));

		return replaceString;
	}

	/**
	 * <h3 class="en-US">Replace special HTML character with converted character in string.</h3>
	 * <h3 class="zh-CN">替换HTML特殊字符为转义字符串</h3>
	 *
	 * @param sourceString <span class="en-US">The string will process</span>
	 *                     <span class="zh-CN">要处理的字符串</span>
	 * @return <span class="en-US">Replaced string</span>
	 * <span class="zh-CN">替换后的字符串</span>
	 */
	public static String textToHtml(final String sourceString) {
		int strLen;
		StringBuilder reString = new StringBuilder();
		strLen = sourceString.length();

		for (int i = 0; i < strLen; i++) {
			char ch = sourceString.charAt(i);
			switch (ch) {
				case '<':
					reString.append("&lt;");
					break;
				case '>':
					reString.append("&gt;");
					break;
				case '\"':
					reString.append("&quot;");
					break;
				case '&':
					reString.append("&amp;");
					break;
				case '\'':
					reString.append("&#39;");
					break;
				case '\\':
					reString.append("\\\\");
					break;
				case FileUtils.LF:
					reString.append("\\n");
					break;
				case FileUtils.CR:
					reString.append("<br/>");
					break;
				default:
					reString.append(Globals.DEFAULT_VALUE_STRING).append(ch);
			}
		}
		return reString.toString();
	}

	/**
	 * <h3 class="en-US">Match given string with regex string</h3>
	 * <h3 class="zh-CN">将给定的字符串与给定的正则表达式字符串做匹配</h3>
	 *
	 * @param str   <span class="en-US">The string will match</span>
	 *              <span class="zh-CN">要匹配的字符串</span>
	 * @param regex <span class="en-US">regex string</span>
	 *              <span class="zh-CN">正则表达式字符串</span>
	 * @return <span class="en-US">Match result</span>
	 * <span class="zh-CN">匹配结果</span>
	 */
	public static boolean matches(final String str, final String regex) {
		if (StringUtils.isEmpty(str) || StringUtils.isEmpty(regex)) {
			return Boolean.FALSE;
		}
		return str.matches(regex);
	}

	/**
	 * <h3 class="en-US">Replace template string using matched value from input string by regex</h3>
	 * <h3 class="zh-CN">使用正则表达式从输入字符串中提取数据并替换模板字符串中对应的值</h3>
	 *
	 * @param str      <span class="en-US">input string</span>
	 *                 <span class="zh-CN">输入字符串</span>
	 * @param regex    <span class="en-US">regex string</span>
	 *                 <span class="zh-CN">正则表达式字符串</span>
	 * @param template <span class="en-US">template string</span>
	 *                 <span class="zh-CN">模板字符串</span>
	 * @return <span class="en-US">Replaced string, or <code>null</code> if input string not matched</span>
	 * <span class="zh-CN">替换后的字符串，如果输入字符串未匹配则返回<code>null</code></span>
	 */
	public static String replaceWithRegex(final String str, final String regex, final String template) {
		return replaceWithRegex(str, regex, template, Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * <h3 class="en-US">Replace template string using matched value from input string by regex</h3>
	 * <h3 class="zh-CN">使用正则表达式从输入字符串中提取数据并替换模板字符串中对应的值</h3>
	 *
	 * @param str             <span class="en-US">input string</span>
	 *                        <span class="zh-CN">输入字符串</span>
	 * @param regex           <span class="en-US">regex string</span>
	 *                        <span class="zh-CN">正则表达式字符串</span>
	 * @param template        <span class="en-US">template string</span>
	 *                        <span class="zh-CN">模板字符串</span>
	 * @param substringPrefix <span class="en-US">the substring prefix</span>
	 *                        <span class="zh-CN">需要去掉的替换值前缀字符</span>
	 * @return <span class="en-US">Replaced string, or <code>null</code> if input string not matched</span>
	 * <span class="zh-CN">替换后的字符串，如果输入字符串未匹配则返回<code>null</code></span>
	 */
	public static String replaceWithRegex(final String str, final String regex, final String template,
	                                      final String substringPrefix) {
		if (!matches(str, regex)) {
			return null;
		}

		String matchResult = template;
		Matcher matcher = Pattern.compile(regex).matcher(str);
		if (matcher.find()) {
			for (int i = 0; i < matcher.groupCount(); i++) {
				int index = i + 1;
				String matchValue = matcher.group(index);
				if (matchValue == null) {
					matchValue = Globals.DEFAULT_VALUE_STRING;
				} else {
					if (StringUtils.notBlank(substringPrefix) && matchValue.startsWith(substringPrefix)) {
						matchValue = matchValue.substring(substringPrefix.length());
					}
				}
				matchResult = replace(matchResult, "$" + index, matchValue);
			}

			return matchResult;
		}
		return str;
	}

	/**
	 * <h3 class="en-US">Generate random string by given length</h3>
	 * <h3 class="zh-CN">根据给定的字符串长度生成随机字符串</h3>
	 *
	 * @param length <span class="en-US">string length</span>
	 *               <span class="zh-CN">字符串长度</span>
	 * @return <span class="en-US">Generated string</span>
	 * <span class="zh-CN">生成的字符串</span>
	 */
	public static String randomString(final int length) {
		StringBuilder generateKey = new StringBuilder();
		SecureRandom random = new SecureRandom();
		for (int i = 0; i < length; i++) {
			generateKey.append(AUTHORIZATION_CODE_ITEMS.charAt(random.nextInt(AUTHORIZATION_CODE_ITEMS.length())));
		}
		return generateKey.toString();
	}

	/**
	 * <h3 class="en-US">Generate random number string by given length</h3>
	 * <h3 class="zh-CN">根据给定的字符串长度生成随机字符串</h3>
	 *
	 * @param length <span class="en-US">string length</span>
	 *               <span class="zh-CN">字符串长度</span>
	 * @return <span class="en-US">Generated string</span>
	 * <span class="zh-CN">生成的字符串</span>
	 */
	public static String randomNumber(final int length) {
		StringBuilder generateKey = new StringBuilder();
		for (int i = 0; i < length; i++) {
			generateKey.append((char) (Math.random() * 10 + '0'));
		}
		return generateKey.toString();
	}

	/**
	 * <h3 class="en-US">Generate random index char</h3>
	 * <h3 class="zh-CN">生成随机索引字符</h3>
	 *
	 * @param beginIndex <span class="en-US">the beginning index</span>
	 *                   <span class="zh-CN">起始索引</span>
	 * @param endIndex   <span class="en-US">the end index</span>
	 *                   <span class="zh-CN">终止索引</span>
	 * @return <span class="en-US">Generated character</span>
	 * <span class="zh-CN">生成的字符</span>
	 */
	public static char randomIndex(final int beginIndex, final int endIndex) {
		return (char) (Math.random() * (endIndex - beginIndex + 1) + beginIndex + '0');
	}

	/**
	 * <h3 class="en-US">Generate random char</h3>
	 * <h3 class="zh-CN">生成随机字符</h3>
	 *
	 * @param beginIndex <span class="en-US">the beginning index</span>
	 *                   <span class="zh-CN">起始索引</span>
	 * @param endIndex   <span class="en-US">the end index</span>
	 *                   <span class="zh-CN">终止索引</span>
	 * @return <span class="en-US">Generated character</span>
	 * <span class="zh-CN">生成的字符</span>
	 */
	public static char randomChar(final int beginIndex, final int endIndex) {
		return (char) (Math.random() * (endIndex - beginIndex + 1) + beginIndex + 'a');
	}

	/**
	 * <h3 class="en-US">Check given character is space</h3>
	 * <h3 class="zh-CN">检查给定字符是否为空格</h3>
	 *
	 * @param letter <span class="en-US">will check for character</span>
	 *               <span class="zh-CN">将要检查的字符</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean isSpace(final char letter) {
		return (letter == 8 || letter == 9 || letter == 10 || letter == 13 || letter == 32 || letter == 160);
	}

	/**
	 * <h3 class="en-US">Check given character is english character</h3>
	 * <h3 class="zh-CN">检查给定字符是否为英文字母</h3>
	 *
	 * @param letter <span class="en-US">will check for character</span>
	 *               <span class="zh-CN">将要检查的字符</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean isEnglish(final char letter) {
		return (letter > 'a' && letter < 'z') || (letter > 'A' && letter < 'Z');
	}

	/**
	 * <h3 class="en-US">Check given character is number</h3>
	 * <h3 class="zh-CN">检查给定字符是否为数字</h3>
	 *
	 * @param letter <span class="en-US">will check for character</span>
	 *               <span class="zh-CN">将要检查的字符</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean isNumber(final char letter) {
		return letter >= '0' && letter <= '9';
	}

	/**
	 * <h3 class="en-US">Check given character is Chinese/Japanese/Korean</h3>
	 * <h3 class="zh-CN">检查给定字符是否为中文/日文/韩文</h3>
	 *
	 * @param letter <span class="en-US">will check for character</span>
	 *               <span class="zh-CN">将要检查的字符</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean isCJK(final char letter) {
		UnicodeBlock unicodeBlock = UnicodeBlock.of(letter);

		return (unicodeBlock == UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS
				|| unicodeBlock == UnicodeBlock.CJK_COMPATIBILITY_IDEOGRAPHS
				|| unicodeBlock == UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS_EXTENSION_A
				|| unicodeBlock == UnicodeBlock.GENERAL_PUNCTUATION
				|| unicodeBlock == UnicodeBlock.CJK_SYMBOLS_AND_PUNCTUATION
				//全角数字字符和日韩字符
				|| unicodeBlock == UnicodeBlock.HALFWIDTH_AND_FULLWIDTH_FORMS
				//韩文字符集
				|| unicodeBlock == UnicodeBlock.HANGUL_SYLLABLES
				|| unicodeBlock == UnicodeBlock.HANGUL_JAMO
				|| unicodeBlock == UnicodeBlock.HANGUL_COMPATIBILITY_JAMO
				//日文字符集
				|| unicodeBlock == UnicodeBlock.HIRAGANA //平假名
				|| unicodeBlock == UnicodeBlock.KATAKANA //片假名
				|| unicodeBlock == UnicodeBlock.KATAKANA_PHONETIC_EXTENSIONS);
	}

	/**
	 * <h3 class="en-US">Check given code string is valid of the given code type</h3>
	 * <h3 class="zh-CN">检查给定代码字符穿是否符合指定代码类型的算法</h3>
	 *
	 * @param code     <span class="en-US">will check for code</span>
	 *                 <span class="zh-CN">将要检查的代码字符串</span>
	 * @param codeType <span class="en-US">Code type</span>
	 *                 <span class="zh-CN">代码类型</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean validateCode(final String code, final CodeType codeType) {
		if (StringUtils.isEmpty(code)) {
			return Boolean.FALSE;
		}
		switch (codeType) {
			case CHN_ID_Code:
				String cardCode = code.toUpperCase();
				if (StringUtils.matches(cardCode, RegexGlobals.CHN_ID_Card)) {
					int validateCode = CHN_ID_CARD_CODE.indexOf(cardCode.charAt(17));
					if (validateCode != -1) {
						int sigma = 0;
						for (int i = 0; i < 17; i++) {
							sigma += (int) (Character.digit(cardCode.charAt(i), 10) * (Math.pow(2, 17 - i) % 11));
						}
						return validateCode == ((12 - (sigma % 11)) % 11);
					}
				}
				break;
			case CHN_Social_Code:
				String creditCode = code.toUpperCase();
				if (StringUtils.matches(creditCode, RegexGlobals.CHN_Social_Credit)) {
					int validateCode = CHN_SOCIAL_CREDIT_CODE.indexOf(creditCode.charAt(17));
					if (validateCode != -1) {
						int sigma = 0;
						for (int i = 0; i < 17; i++) {
							sigma += (int) (CHN_SOCIAL_CREDIT_CODE.indexOf(creditCode.charAt(i)) * (Math.pow(3, i) % 31));
						}

						int authCode = 31 - (sigma % 31);
						return (authCode == 31) ? (validateCode == 0) : (authCode == validateCode);
					}
				}
				break;
			case Luhn:
				if (StringUtils.matches(code, RegexGlobals.LUHN)) {
					int result = 0, length = code.length();
					for (int i = 0; i < length; i++) {
						int currentCode = Character.getNumericValue(code.charAt(length - i - 1));
						if (i % 2 == 1) {
							currentCode *= 2;
							if (currentCode > 9) {
								currentCode -= 9;
							}
						}
						result += currentCode;
					}
					return result % 10 == 0;
				}
				break;
		}
		return Boolean.FALSE;
	}

	/**
	 * <h2 class="en-US">Enumeration of String Type</h2>
	 * <h2 class="zh-CN">字符串类型的枚举类</h2>
	 */
	public enum StringType {
		JSON, YAML, XML, SIMPLE, SERIALIZABLE
	}

	/**
	 * <h2 class="en-US">Enumeration of Code Type</h2>
	 * <h2 class="zh-CN">代码类型的枚举类</h2>
	 */
	public enum CodeType {
		CHN_Social_Code, CHN_ID_Code, Luhn
	}

	/**
	 * <h3 class="en-US">Parse strings to target JavaBean instance. </h3>
	 * <h3 class="zh-CN">解析字符串为目标JavaBean实例对象</h3>
	 *
	 * @param <T>         <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param string      <span class="en-US">The string will parse</span>
	 *                    <span class="zh-CN">要解析的字符串</span>
	 * @param stringType  <span class="en-US">The string type</span>
	 *                    <span class="zh-CN">字符串类型</span>
	 * @param encoding    <span class="en-US">String charset encoding</span>
	 *                    <span class="zh-CN">字符串的字符集编码</span>
	 * @param beanClass   <span class="en-US">target JavaBean class</span>
	 *                    <span class="zh-CN">目标JavaBean类</span>
	 * @param schemaPaths <span class="en-US">XML schema path(Maybe schema uri or local path)</span>
	 *                    <span class="zh-CN">XML描述文件路径（可能为描述文件URI或本地文件路径）</span>
	 * @return <span class="en-US">Converted object instance</span>
	 * <span class="zh-CN">转换后的实例对象</span>
	 */
	private static <T> T stringToObject(final String string, final StringType stringType, final String encoding,
	                                    final Class<T> beanClass, final String... schemaPaths) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Parse_String_Debug", string, encoding, beanClass.getName());
		}

		if (StringType.SIMPLE.equals(stringType)) {
			return ClassUtils.parseSimpleData(string, beanClass);
		}
		String stringEncoding = (encoding == null) ? Globals.DEFAULT_ENCODING : encoding;
		try (InputStream inputStream = new ByteArrayInputStream(string.getBytes(stringEncoding))) {
			return streamToObject(inputStream, stringType, beanClass, schemaPaths);
		} catch (IOException e) {
			LOGGER.error("Parse_String_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}
		return null;
	}

	/**
	 * <h3 class="en-US">change the first letter to the given capitalize</h3>
	 * <h3 class="zh-CN">转换字符串的第一个字符为大/小写</h3>
	 *
	 * @param str        <span class="en-US">the String to capitalize, maybe <code>null</code></span>
	 *                   <span class="zh-CN">要大写的字符串，可能为 null</span>
	 * @param capitalize <span class="en-US">capitalize status</span>
	 *                   <span class="zh-CN">大小写状态</span>
	 * @return <span class="en-US">the capitalized String, or <code>null</code> if parameter str is <code>null</code></span>
	 * <span class="zh-CN">大写字符串，如果参数 str 为 <code>null</code>，则为 <code>null</code></span>
	 */
	private static String changeFirstCharacterCase(final String str, final boolean capitalize) {
		if (str == null || str.isEmpty()) {
			return str;
		}
		StringBuilder buf = new StringBuilder(str.length());
		if (capitalize) {
			buf.append(Character.toUpperCase(str.charAt(0)));
		} else {
			buf.append(Character.toLowerCase(str.charAt(0)));
		}
		buf.append(str.substring(1));
		return buf.toString();
	}

	/**
	 * <h3 class="en-US">Register URL instance of the schema mapping file</h3>
	 * <h3 class="zh-CN">从URL实例对象中读取XML约束文档的资源映射文件内容并注册</h3>
	 *
	 * @param url <span class="en-US">URL instance</span>
	 *            <span class="zh-CN">URL实例对象</span>
	 */
	private static void REGISTER_SCHEMA(final URL url) {
		String basePath = url.getPath();
		ConvertUtils.toMap(url, new HashMap<>())
				.forEach((key, value) ->
						SCHEMA_MAPPING.put(key, StringUtils.replace(basePath, SCHEMA_MAPPING_RESOURCE_PATH, value)));
	}

	/**
	 * <h3 class="en-US">Generate a Schema instance object according to the given XML description file path.</h3>
	 * <h3 class="zh-CN">根据给定的XML描述文件路径，生成Schema实例对象</h3>
	 *
	 * @param schemaPaths <span class="en-US">XML schema path(Maybe schema uri or local path)</span>
	 *                    <span class="zh-CN">XML描述文件路径（可能为描述文件URI或本地文件路径）</span>
	 * @return <span class="en-US">Generated Schema instance</span>
	 * <span class="zh-CN">生成的Schema实例对象</span>
	 */
	private static Schema newSchema(final String... schemaPaths) {
		if (CollectionUtils.isEmpty(schemaPaths)) {
			return null;
		}
		SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		schemaFactory.setResourceResolver(new SchemaResourceResolver());
		try {
			Source[] sources = new Source[schemaPaths.length];
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			docFactory.setNamespaceAware(Boolean.TRUE);
			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
			for (int i = 0; i < schemaPaths.length; i++) {
				String locationPath = SCHEMA_MAPPING.getOrDefault(schemaPaths[i], schemaPaths[i]);
				InputStream in = FileUtils.loadFile(locationPath);
				Document document = docBuilder.parse(in);
				sources[i] = new DOMSource(document, locationPath);
				IOUtils.closeStream(in);
			}
			return schemaFactory.newSchema(sources);
		} catch (ParserConfigurationException | SAXException | IOException e) {
			LOGGER.error("Load_Schemas_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Private constructor for StringUtils</h3>
	 * <h3 class="zh-CN">字符串工具集的私有构造方法</h3>
	 */
	private StringUtils() {
	}

	/**
	 * <h2 class="en-US">Schema resource resolver for support schema mapping</h2>
	 * <h2 class="zh-CN">支持自定义资源描述文件映射的资源文件解析器</h2>
	 */
	private static final class SchemaResourceResolver implements LSResourceResolver {
		/**
		 * (Non-Javadoc)
		 *
		 * @see LSResourceResolver#resolveResource(String, String, String, String, String)
		 */
		@Override
		public LSInput resolveResource(final String type, final String namespaceURI, final String publicId,
		                               final String systemId, final String baseURI) {
			LOGGER.debug("Resolving_Schema_Debug",
					type, namespaceURI, publicId, systemId, baseURI);
			String schemaLocation = baseURI.substring(0, baseURI.lastIndexOf("/") + 1);
			String filePath;
			if (SCHEMA_MAPPING.containsKey(namespaceURI)) {
				filePath = SCHEMA_MAPPING.get(namespaceURI);
			} else {
				if (!systemId.contains(Globals.HTTP_PROTOCOL)) {
					filePath = schemaLocation + systemId;
				} else {
					filePath = systemId;
				}
			}
			try {
				return new LSInputImpl(publicId, namespaceURI, FileUtils.loadFile(filePath));
			} catch (IOException e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Load_Schemas_Error", e);
				}
				return new LSInputImpl();
			}
		}
	}

	/**
	 * <h2 class="en-US">Implement class for LSInput</h2>
	 * <h2 class="zh-CN">LSInput的实现类</h2>
	 */
	private static final class LSInputImpl implements LSInput {
		private String publicId;
		private String systemId;
		private String baseURI;
		private InputStream byteStream;
		private Reader characterStream;
		private String stringData;
		private String encoding;
		private boolean certifiedText;

		/**
		 * <h3 class="en-US">Default constructor for LSInputImpl</h3>
		 * <h3 class="zh-CN">LSInputImpl的私有构造方法</h3>
		 */
		LSInputImpl() {
		}

		/**
		 * <h3 class="en-US">Default constructor for LSInputImpl</h3>
		 * <h3 class="zh-CN">LSInputImpl的私有构造方法</h3>
		 *
		 * @param publicId   <span class="en-US">Public ID</span>
		 *                   <span class="zh-CN">Public ID</span>
		 * @param systemId   <span class="en-US">Namespace URI</span>
		 *                   <span class="zh-CN">命名空间URI</span>
		 * @param byteStream <span class="en-US">Input stream of schema file</span>
		 *                   <span class="zh-CN">描述文件的输入流</span>
		 */
		LSInputImpl(final String publicId, final String systemId, final InputStream byteStream) {
			this.publicId = publicId;
			this.systemId = systemId;
			this.byteStream = byteStream;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#getPublicId()
		 */
		@Override
		public String getPublicId() {
			return publicId;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#setPublicId(String)
		 */
		@Override
		public void setPublicId(String publicId) {
			this.publicId = publicId;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#getSystemId()
		 */
		@Override
		public String getSystemId() {
			return systemId;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#setSystemId(String)
		 */
		@Override
		public void setSystemId(String systemId) {
			this.systemId = systemId;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#getBaseURI()
		 */
		@Override
		public String getBaseURI() {
			return baseURI;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#setBaseURI(String)
		 */
		@Override
		public void setBaseURI(String baseURI) {
			this.baseURI = baseURI;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#getByteStream()
		 */
		@Override
		public InputStream getByteStream() {
			return byteStream;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#setByteStream(InputStream)
		 */
		@Override
		public void setByteStream(InputStream byteStream) {
			this.byteStream = byteStream;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#getCharacterStream()
		 */
		@Override
		public Reader getCharacterStream() {
			return characterStream;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#setCharacterStream(Reader)
		 */
		@Override
		public void setCharacterStream(Reader characterStream) {
			this.characterStream = characterStream;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#getStringData()
		 */
		@Override
		public String getStringData() {
			return stringData;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#setStringData(String)
		 */
		@Override
		public void setStringData(String stringData) {
			this.stringData = stringData;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#getEncoding()
		 */
		@Override
		public String getEncoding() {
			return encoding;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#setEncoding(String)
		 */
		@Override
		public void setEncoding(String encoding) {
			this.encoding = encoding;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#getCertifiedText()
		 */
		@Override
		public boolean getCertifiedText() {
			return certifiedText;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see LSInput#setCertifiedText(boolean)
		 */
		@Override
		public void setCertifiedText(boolean certifiedText) {
			this.certifiedText = certifiedText;
		}
	}

	/**
	 * Writer for output CData string
	 */
	private static final class CDataStreamWriter implements XMLStreamWriter {

		private final XMLStreamWriter xmlStreamWriter;

		/**
		 * Instantiates a new C data stream writer.
		 *
		 * @param xmlStreamWriter the XML stream writer
		 */
		CDataStreamWriter(final XMLStreamWriter xmlStreamWriter) {
			this.xmlStreamWriter = xmlStreamWriter;
		}

		/**
		 * Writes a start tag to the output.
		 * All writeStartElement methods open a new scope in the internal namespace context.
		 * Writing the corresponding EndElement causes the scope to be closed.
		 *
		 * @param localName the local name of the tag may not be null
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeStartElement(final String localName) throws XMLStreamException {
			this.xmlStreamWriter.writeStartElement(localName);
		}

		/**
		 * Writes a start tag to the output
		 *
		 * @param namespaceURI the namespaceURI of the prefix to use, may not be null
		 * @param localName    the local name of the tag may not be null
		 * @throws XMLStreamException if the namespace URI has not been bound to a prefix and
		 *                            javax.xml.stream.isRepairingNamespaces has not been set to true
		 */
		@Override
		public void writeStartElement(final String namespaceURI, final String localName) throws XMLStreamException {
			this.xmlStreamWriter.writeStartElement(namespaceURI, localName);
		}

		/**
		 * Writes a start tag to the output
		 *
		 * @param prefix       the prefix of the tag may not be null
		 * @param localName    the local name of the tag may not be null
		 * @param namespaceURI the uri to bind the prefix to, may not be null
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeStartElement(final String prefix, final String localName, final String namespaceURI)
				throws XMLStreamException {
			this.xmlStreamWriter.writeStartElement(prefix, localName, namespaceURI);
		}

		/**
		 * Writes an empty element tag to the output
		 *
		 * @param namespaceURI the uri to bind the tag to, may not be null
		 * @param localName    the local name of the tag may not be null
		 * @throws XMLStreamException if the namespace URI has not been bound to a prefix and
		 *                            javax.xml.stream.isRepairingNamespaces has not been set to true
		 */
		@Override
		public void writeEmptyElement(final String namespaceURI, final String localName) throws XMLStreamException {
			this.xmlStreamWriter.writeEmptyElement(namespaceURI, localName);
		}

		/**
		 * Writes an empty element tag to the output
		 *
		 * @param prefix       the prefix of the tag may not be null
		 * @param localName    the local name of the tag may not be null
		 * @param namespaceURI the uri to bind the tag to, may not be null
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeEmptyElement(final String prefix, final String localName, final String namespaceURI)
				throws XMLStreamException {
			this.xmlStreamWriter.writeEmptyElement(prefix, localName, namespaceURI);
		}

		/**
		 * Writes an empty element tag to the output
		 *
		 * @param localName the local name of the tag may not be null
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeEmptyElement(final String localName) throws XMLStreamException {
			this.xmlStreamWriter.writeEmptyElement(localName);
		}

		/**
		 * Writes an end tag to the output relying on the internal
		 * state of the writer to determine the prefix and local name
		 * of the event.
		 *
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeEndElement() throws XMLStreamException {
			this.xmlStreamWriter.writeEndElement();
		}

		/**
		 * Closes any start tags and writes corresponding end tags.
		 *
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeEndDocument() throws XMLStreamException {
			this.xmlStreamWriter.writeEndDocument();
		}

		/**
		 * Close this writer and free any resources associated with the writer.
		 * This must not close the underlying output stream.
		 *
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void close() throws XMLStreamException {
			this.xmlStreamWriter.close();
		}

		/**
		 * Write any cached data to the underlying output mechanism.
		 *
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void flush() throws XMLStreamException {
			this.xmlStreamWriter.flush();
		}

		/**
		 * Writes an attribute to the output stream without
		 * a prefix.
		 *
		 * @param localName the local name of the attribute
		 * @param value     the value of the attribute
		 * @throws IllegalStateException if the current state does not allow Attribute writing
		 * @throws XMLStreamException    if the namespace URI has not been bound to a prefix and
		 *                               javax.xml.stream.isRepairingNamespaces has not been set to true
		 */
		@Override
		public void writeAttribute(final String localName, final String value) throws XMLStreamException {
			this.xmlStreamWriter.writeAttribute(localName, value);
		}

		/**
		 * Writes an attribute to the output stream
		 *
		 * @param prefix       the prefix for this attribute
		 * @param namespaceURI the uri of the prefix for this attribute
		 * @param localName    the local name of the attribute
		 * @param value        the value of the attribute
		 * @throws IllegalStateException if the current state does not allow Attribute writing
		 * @throws XMLStreamException    if the namespace URI has not been bound to a prefix and
		 *                               javax.xml.stream.isRepairingNamespaces has not been set to true
		 */
		@Override
		public void writeAttribute(final String prefix, final String namespaceURI,
		                           final String localName, final String value) throws XMLStreamException {
			this.xmlStreamWriter.writeAttribute(prefix, namespaceURI, localName, value);
		}

		/**
		 * Writes an attribute to the output stream
		 *
		 * @param namespaceURI the uri of the prefix for this attribute
		 * @param localName    the local name of the attribute
		 * @param value        the value of the attribute
		 * @throws IllegalStateException if the current state does not allow Attribute writing
		 * @throws XMLStreamException    if the namespace URI has not been bound to a prefix and
		 *                               javax.xml.stream.isRepairingNamespaces has not been set to true
		 */
		@Override
		public void writeAttribute(final String namespaceURI, final String localName, final String value)
				throws XMLStreamException {
			this.xmlStreamWriter.writeAttribute(namespaceURI, localName, value);
		}

		/**
		 * Writes a namespace to the output stream
		 * If the prefix argument to this method is the empty string,
		 * "xmlns" or null this method will delegate to writeDefaultNamespace
		 *
		 * @param prefix       the prefix to bind this namespace to
		 * @param namespaceURI the uri to bind the prefix to
		 * @throws IllegalStateException if the current state does not allow Namespace writing
		 * @throws XMLStreamException    XMLStreamException
		 */
		@Override
		public void writeNamespace(final String prefix, final String namespaceURI) throws XMLStreamException {
			this.xmlStreamWriter.writeNamespace(prefix, namespaceURI);
		}

		/**
		 * Writes the default namespace to the stream
		 *
		 * @param namespaceURI the uri to bind the default namespace to
		 * @throws IllegalStateException if the current state does not allow Namespace writing
		 * @throws XMLStreamException    XMLStreamException
		 */
		@Override
		public void writeDefaultNamespace(final String namespaceURI) throws XMLStreamException {
			this.xmlStreamWriter.writeDefaultNamespace(namespaceURI);
		}

		/**
		 * Writes a XML comment with the data enclosed
		 *
		 * @param data the data contained in the comment, may be null
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeComment(final String data) throws XMLStreamException {
			this.xmlStreamWriter.writeComment(data);
		}

		/**
		 * Writes a processing instruction
		 *
		 * @param target the target of the processing instruction may not be null
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeProcessingInstruction(final String target) throws XMLStreamException {
			this.xmlStreamWriter.writeProcessingInstruction(target);
		}

		/**
		 * Writes a processing instruction
		 *
		 * @param target the target of the processing instruction may not be null
		 * @param data   the data contained in the processing instruction, may not be null
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeProcessingInstruction(final String target, final String data) throws XMLStreamException {
			this.xmlStreamWriter.writeProcessingInstruction(target, data);
		}

		/**
		 * Writes a CData section
		 *
		 * @param data the data contained in the CData Section, may not be null
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeCData(final String data) throws XMLStreamException {
			this.xmlStreamWriter.writeCData(data);
		}

		/**
		 * Write a DTD section.
		 * This string represents the entire doc type decl production from the XML 1.0 specification.
		 *
		 * @param dtd the DTD to be written
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeDTD(final String dtd) throws XMLStreamException {
			this.xmlStreamWriter.writeDTD(dtd);
		}

		/**
		 * Writes an entity reference
		 *
		 * @param name the name of the entity
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeEntityRef(final String name) throws XMLStreamException {
			this.xmlStreamWriter.writeEntityRef(name);
		}

		/**
		 * Write the XML Declaration. Defaults the XML version to 1.0, and the encoding to utf-8
		 *
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeStartDocument() throws XMLStreamException {
			this.xmlStreamWriter.writeStartDocument();
		}

		/**
		 * Write the XML Declaration. Defaults the XML version to 1.0
		 *
		 * @param version version of the XML document
		 * @throws XMLStreamException If given encoding does not match encoding
		 *                            of the underlying stream
		 */
		@Override
		public void writeStartDocument(final String version) throws XMLStreamException {
			this.xmlStreamWriter.writeStartDocument(version);
		}

		/**
		 * Write the XML Declaration.
		 * Note that the encoding parameter does not set the actual encoding of the underlying output.
		 * That must be set when the instance of the XMLStreamWriter is created using the
		 * XMLOutputFactory
		 *
		 * @param encoding encoding of the XML declaration
		 * @param version  version of the XML document
		 * @throws XMLStreamException If given encoding does not match encoding
		 *                            of the underlying stream
		 */
		@Override
		public void writeStartDocument(final String encoding, final String version) throws XMLStreamException {
			this.xmlStreamWriter.writeStartDocument(encoding, version);
		}

		/**
		 * Write text to the output
		 *
		 * @param text the value to write
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeCharacters(final String text) throws XMLStreamException {
			if (text.startsWith(CDataAdapter.CDATA_BEGIN) && text.endsWith(CDataAdapter.CDATA_END)) {
				this.writeCData(text.substring(CDataAdapter.CDATA_BEGIN.length(),
						text.length() - CDataAdapter.CDATA_END.length()));
			} else {
				this.xmlStreamWriter.writeCharacters(text);
			}
		}

		/**
		 * Write text to the output
		 *
		 * @param text  the value to write
		 * @param start the starting position in the array
		 * @param len   the number of characters to write
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void writeCharacters(final char[] text, final int start, final int len) throws XMLStreamException {
			this.writeCharacters(new String(text, start, len));
		}

		/**
		 * Gets the prefix the uri is bound to
		 *
		 * @param uri the uri to bind to the prefix
		 * @return the prefix or null
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public String getPrefix(final String uri) throws XMLStreamException {
			return this.xmlStreamWriter.getPrefix(uri);
		}

		/**
		 * Sets the prefix the uri is bound to.
		 * This prefix is bound in the scope of the current START_ELEMENT / END_ELEMENT pair.
		 * If this method is called before a START_ELEMENT has been written,
		 * the prefix is bound in the root scope.
		 *
		 * @param prefix the prefix to bind to the uri, may not be null
		 * @param uri    the uri to bind to the prefix, may be null
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void setPrefix(final String prefix, final String uri) throws XMLStreamException {
			this.xmlStreamWriter.setPrefix(prefix, uri);
		}

		/**
		 * Binds a URI to the default namespace
		 * This URI is bound
		 * in the scope of the current START_ELEMENT / END_ELEMENT pair.
		 * If this method is called before a START_ELEMENT has been written,
		 * the uri is bound in the root scope.
		 *
		 * @param uri the uri to bind to the default namespace, may be null
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void setDefaultNamespace(final String uri) throws XMLStreamException {
			this.xmlStreamWriter.setDefaultNamespace(uri);
		}

		/**
		 * Sets the current namespace context for prefix and uri bindings.
		 * This context becomes the root namespace context for writing and
		 * will replace the current root namespace context.
		 * Further calls to setPrefix and setDefaultNamespace will bind namespaces using
		 * the context passed to the method as the root context for resolving namespaces.
		 * This method may only be called once at the start of the document.
		 * It does not cause the namespaces to be declared.
		 * If a namespace URI to prefix mapping is found in the namespace
		 * context, it is treated as declared and the prefix may be used
		 * by the StreamWriter.
		 *
		 * @param context the namespace context to use for this writer, may not be null
		 * @throws XMLStreamException XMLStreamException
		 */
		@Override
		public void setNamespaceContext(final NamespaceContext context) throws XMLStreamException {
			this.xmlStreamWriter.setNamespaceContext(context);
		}

		/**
		 * Returns the current namespace context.
		 *
		 * @return the current NamespaceContext
		 */
		@Override
		public NamespaceContext getNamespaceContext() {
			return this.xmlStreamWriter.getNamespaceContext();
		}

		/**
		 * Get the value of a feature/property from the underlying implementation
		 *
		 * @param name The name of the property may not be null
		 * @return The value of the property
		 * @throws IllegalArgumentException if the property is not supported
		 * @throws NullPointerException     if the name is null
		 */
		@Override
		public Object getProperty(final String name) throws IllegalArgumentException {
			return this.xmlStreamWriter.getProperty(name);
		}
	}
}
