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
package org.nervousync.i18n;

import jakarta.annotation.Nonnull;
import org.nervousync.beans.i18n.BundleError;
import org.nervousync.beans.i18n.BundleLanguage;
import org.nervousync.commons.Globals;
import org.nervousync.utils.MultilingualUtils;
import org.nervousync.utils.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.MessageFormat;
import java.util.*;

/**
 * <h2 class="en-US">Internationalization Message Resources Define</h2>
 * <h2 class="zh-CN">国际化信息资源定义</h2>
 * .0
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 19, 2023 16:39:41 $
 */
public final class MessageResource {

	/**
	 * <span class="en-US">Logger instance</span>
	 * <span class="zh-CN">日志实例</span>
	 */
	private final Logger logger = LoggerFactory.getLogger(this.getClass());
	/**
	 * <span class="en-US">Mapping table of error codes and resource keys</span>
	 * <span class="zh-CN">错误代码与资源索引的映射表</span>
	 */
	private final Map<Long, String> codeKeysMap = new HashMap<>();
	/**
	 * <span class="en-US">Resource information map</span>
	 * <span class="zh-CN">资源信息映射表</span>
	 */
	private final Map<String, String> resourcesMap = new HashMap<>();
	/**
	 * <span class="en-US">Cached resource formatter map</span>
	 * <span class="zh-CN">缓存的资源信息格式化器实例映射表</span>
	 */
	private final Map<String, MessageFormat> cachedFormaterMap = new HashMap<>();
	/**
	 * <span class="en-US">Registered language code information</span>
	 * <span class="zh-CN">注册的语言代码信息</span>
	 */
	private final Map<String, String> registeredLanguages = new HashMap<>();

	/**
	 * <h3 class="en-US">Constructor for Resource</h3>
	 * <h3 class="zh-CN">国际化资源的构造方法</h3>
	 */
	public MessageResource() {
	}

	/**
	 * <h3 class="en-US">Update resource messages</h3>
	 * <h3 class="zh-CN">更新国际化信息内容</h3>
	 *
	 * @param errors    <span class="en-US">Definition list of error codes and message identification codes</span>
	 *                  <span class="zh-CN">错误代码与信息识别代码的定义列表</span>
	 * @param languages <span class="en-US">Definitions of message language list, identification codes and message content</span>
	 *                  <span class="zh-CN">信息语言、识别代码与信息内容的定义列表</span>
	 */
	public void updateResource(@Nonnull final List<BundleError> errors, @Nonnull final List<BundleLanguage> languages) {
		errors.stream()
				.filter(bundleError -> MultilingualUtils.notBlank(bundleError.getErrorCode()))
				.forEach(bundleError -> {
					int radix;
					if (bundleError.getErrorCode().length() > 2) {
						switch (bundleError.getErrorCode().substring(0, 2).toLowerCase()) {
							case "0x":
								radix = 16;
								break;
							case "0o":
								radix = 8;
								break;
							case "0b":
								radix = 2;
								break;
							default:
								radix = 10;
								break;
						}
					} else {
						radix = 10;
					}
					String errorString =
							(radix == 10) ? bundleError.getErrorCode() : bundleError.getErrorCode().substring(2);
					long errorCode = Long.valueOf(errorString, radix);
					if (this.codeKeysMap.containsKey(errorCode)) {
						this.logger.warn("Override error code: {}, original message key: {}, new message key: {}",
								errorCode, this.codeKeysMap.get(errorCode), bundleError.getMessageKey());
					}
					this.codeKeysMap.put(errorCode, bundleError.getMessageKey());
				});
		languages.stream()
				.filter(bundleLanguage -> MultilingualUtils.notBlank(bundleLanguage.getLanguageCode()))
				.forEach(bundleLanguage -> {
					String languageCode = bundleLanguage.getLanguageCode();
					bundleLanguage.getBundleMessages()
							.stream()
							.filter(bundleMessage -> MultilingualUtils.notBlank(bundleMessage.getMessageKey())
									&& MultilingualUtils.notBlank(bundleMessage.getMessageContent()))
							.forEach(bundleMessage -> {
								String messageKey = bundleMessage.getMessageKey();
								String identifyKey = MultilingualUtils.identifyKey(messageKey, languageCode);
								if (this.resourcesMap.containsKey(identifyKey)) {
									this.cachedFormaterMap.remove(identifyKey);
									this.logger.warn("Override resource key: {}, language code: {}, original value: {}, new value: {}",
											messageKey, languageCode, this.resourcesMap.get(identifyKey),
											bundleMessage.getMessageContent());
								}
								this.resourcesMap.put(identifyKey, bundleMessage.getMessageContent());
							});
					if (!this.registeredLanguages.containsKey(languageCode)) {
						this.registeredLanguages.put(languageCode, bundleLanguage.getLanguageName());
					}
				});
	}

	/**
	 * <h3 class="en-US">Retrieve internationalization information content and formatted by given collections</h3>
	 * <h3 class="zh-CN">读取国际化资源信息详情并使用给定的参数集合格式化资源信息</h3>
	 *
	 * @param errorCode       <span class="en-US">Error code</span>
	 *                        <span class="zh-CN">错误代码</span>
	 * @param languageCode    <span class="en-US">Language code</span>
	 *                        <span class="zh-CN">语言代码</span>
	 * @param defaultLanguage <span class="en-US">Default language code</span>
	 *                        <span class="zh-CN">默认语言代码</span>
	 * @param collections     <span class="en-US">given parameters of information formatter</span>
	 *                        <span class="zh-CN">用于资源信息格式化的参数</span>
	 * @return <span class="en-US">Formatted resource information or empty string if not found</span>
	 * <span class="zh-CN">格式化的资源信息，如果未找到则返回空字符串</span>
	 */
	public String findMessage(final long errorCode, final String languageCode,
	                          final String defaultLanguage, final Object... collections) {
		return Optional.ofNullable(this.codeKeysMap.get(errorCode))
				.map(messageKey -> this.findMessage(messageKey, languageCode, defaultLanguage, collections))
				.filter(StringUtils::notBlank)
				.orElse(MultilingualUtils.identifyKey(Long.toString(errorCode), languageCode));
	}

	/**
	 * <h3 class="en-US">Retrieve internationalization information content and formatted by given collections</h3>
	 * <h3 class="zh-CN">读取国际化资源信息详情并使用给定的参数集合格式化资源信息</h3>
	 *
	 * @param messageKey      <span class="en-US">Message identify key</span>
	 *                        <span class="zh-CN">信息识别键值</span>
	 * @param languageCode    <span class="en-US">Language code</span>
	 *                        <span class="zh-CN">语言代码</span>
	 * @param defaultLanguage <span class="en-US">Default language code</span>
	 *                        <span class="zh-CN">默认语言代码</span>
	 * @param collections     <span class="en-US">given parameters of information formatter</span>
	 *                        <span class="zh-CN">用于资源信息格式化的参数</span>
	 * @return <span class="en-US">Formatted resource information or empty string if not found</span>
	 * <span class="zh-CN">格式化的资源信息，如果未找到则返回空字符串</span>
	 */
	public String findMessage(final String messageKey, final String languageCode,
	                          final String defaultLanguage, final Object... collections) {
		if (StringUtils.isEmpty(languageCode)) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		String identifyKey = MultilingualUtils.identifyKey(messageKey, languageCode);
		if (!this.resourcesMap.containsKey(identifyKey)) {
			identifyKey = MultilingualUtils.identifyKey(messageKey, defaultLanguage);
		}
		return Optional.ofNullable(this.retrieveFormatter(identifyKey))
				.map(messageFormat -> messageFormat.format(collections))
				.orElse(MultilingualUtils.identifyKey(messageKey, languageCode));
	}

	/**
	 * <h3 class="en-US">Getter method for registered language code information</h3>
	 * <h3 class="zh-CN">注册的语言代码信息的Getter方法</h3>
	 *
	 * @return <span class="en-US">Registered language code information</span>
	 * <span class="zh-CN">注册的语言代码信息</span>
	 */
	public Map<String, String> getRegisteredLanguages() {
		return registeredLanguages;
	}

	/**
	 * <h3 class="en-US">Retrieve message formatter instance</h3>
	 * <h3 class="zh-CN">读取信息格式化器实例对象</h3>
	 *
	 * @param identifyKey <span class="en-US">Message identify key</span>
	 *                    <span class="zh-CN">信息识别键值</span>
	 * @return <span class="en-US">Retrieved message formatter instance or <code>null</code> if argument messageKey is <code>null</code> or empty string</span>
	 * <span class="zh-CN">读取的信息格式化器实例对象，如果参数 messageKey 未找到或为空字符串，则返回 <code>null</code></span>
	 */
	private MessageFormat retrieveFormatter(final String identifyKey) {
		if (StringUtils.isEmpty(identifyKey)) {
			return null;
		}
		MessageFormat messageFormat = null;
		if (this.resourcesMap.containsKey(identifyKey)) {
			if (this.cachedFormaterMap.containsKey(identifyKey)) {
				messageFormat = this.cachedFormaterMap.get(identifyKey);
			} else {
				messageFormat = new MessageFormat(this.resourcesMap.get(identifyKey));
				this.cachedFormaterMap.put(identifyKey, messageFormat);
			}
		}
		return messageFormat;
	}
}
