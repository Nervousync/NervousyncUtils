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
import org.nervousync.annotations.provider.Provider;
import org.nervousync.beans.i18n.BundleResource;
import org.nervousync.commons.Globals;
import org.nervousync.i18n.MessageResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.*;

/**
 * <h2 class="en-US">Internationalization Utilities</h2>
 * <h2 class="zh-CN">国际化工具集</h2>
 * .0
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 19, 2023 16:39:41 $
 */
public final class MultilingualUtils {
	/**
	 * <span class="en-US">Logger instance</span>
	 * <span class="zh-CN">日志实例</span>
	 */
	private final static Logger LOGGER = LoggerFactory.getLogger(MultilingualUtils.class);
	private static final String DEFAULT_SPLIT_CHARACTER = "_";

	/**
	 * <span class="en-US">Registered resources map</span>
	 * <span class="zh-CN">已注册的资源信息映射表</span>
	 */
	private static final Map<String, MessageResource> REGISTERED_RESOURCES = new HashMap<>();
	private static final Map<String, String> IDENTIFY_KEY_MAP = new HashMap<>();
	/**
	 * <span class="en-US">Default locale instance, usually value is default locale for this instance of the Java Virtual Machine.</span>
	 * <span class="zh-CN">默认区域设置实例，通常值是 Java 虚拟机实例的默认区域设置。</span>
	 */
	private static String DEFAULT_LANGUAGE_CODE = toLanguageCode(Globals.DEFAULT_LOCALE);
	/**
	 * <span class="en-US">XML Schema file mapping resource path</span>
	 * <span class="zh-CN">XML约束文档的资源映射文件</span>
	 */
	public static final String BUNDLE_RESOURCE_PATH = "META-INF/nervousync.i18n";
	private static final Map<String, String> REGISTERED_LANGUAGES = new HashMap<>();
	private static final List<String> ENABLED_LANGUAGES = new ArrayList<>();

	static {
		try {
			ClassUtils.getDefaultClassLoader().getResources(BUNDLE_RESOURCE_PATH)
					.asIterator()
					.forEachRemaining(MultilingualUtils::registerBundle);
		} catch (IOException ignore) {
		}
		enableLanguages();
	}

	/**
	 * <h3 class="en-US">Private constructor for MultilingualUtils</h3>
	 * <h3 class="zh-CN">国际化工具集的私有构造方法</h3>
	 */
	private MultilingualUtils() {
	}

	/**
	 * <h3 class="en-US">Convert locale instance to string.</h3>
	 * <h3 class="zh-CN">将语言环境实例转换为字符串。</h3>
	 *
	 * @param locale <span class="en-US">locale instance</span>
	 *               <span class="zh-CN">区域设置实例</span>
	 * @return <span class="en-US">Converted string</span>
	 * <span class="zh-CN">转换后的字符串</span>
	 */
	public static String toLanguageCode(@Nonnull final Locale locale) {
		return Optional.of(locale.getCountry())
				.filter(StringUtils::notBlank)
				.map(countryCode -> locale.getLanguage() + "-" + countryCode)
				.orElse(locale.getLanguage());
	}

	/**
	 * <h3 class="en-US">Configure default locale</h3>
	 * <h3 class="zh-CN">设置默认语言</h3>
	 *
	 * @param locale <span class="en-US">Default locale instance</span>
	 *               <span class="zh-CN">默认区域设置实例</span>
	 */
	public static void defaultLocale(@Nonnull final Locale locale) {
		DEFAULT_LANGUAGE_CODE = toLanguageCode(locale);
	}

	/**
	 * <h3 class="en-US">Generate multilingual agent instance</h3>
	 * <h3 class="zh-CN">生成国际化代理实例对象</h3>
	 *
	 * @param groupId <span class="en-US">Resource group id</span>
	 *                <span class="zh-CN">资源的组ID</span>
	 * @param bundle  <span class="en-US">Resource bundle</span>
	 *                <span class="zh-CN">资源的标识</span>
	 * @return <span class="en-US">Generated instance</span>
	 * <span class="zh-CN">生成的实例对象</span>
	 */
	public static Agent newAgent(final String groupId, final String bundle) {
		return new Agent(groupId, bundle);
	}

	/**
	 * <h3 class="en-US">Generate multilingual agent instance</h3>
	 * <h3 class="zh-CN">生成国际化代理实例对象</h3>
	 *
	 * @param clazz <span class="en-US">Class instance</span>
	 *              <span class="zh-CN">类实例对象</span>
	 * @return <span class="en-US">Generated instance</span>
	 * <span class="zh-CN">生成的实例对象</span>
	 */
	public static Agent newAgent(final Class<?> clazz) {
		return new Agent(clazz);
	}

	/**
	 * <h3 class="en-US">Get the language name corresponding to the given language code</h3>
	 * <h3 class="zh-CN">获取给定语言代码对应的语言名称</h3>
	 *
	 * @param languageCode <span class="en-US">Language code</span>
	 *                     <span class="zh-CN">语言代码</span>
	 * @return <span class="en-US">Language name</span>
	 * <span class="zh-CN">语言名称</span>
	 */
	public static String languageName(final String languageCode) {
		return REGISTERED_LANGUAGES.get(languageCode);
	}

	/**
	 * <h3 class="en-US">Get the name of the given adapter implementation class</h3>
	 * <h3 class="zh-CN">获取给定适配器实现类的名称</h3>
	 *
	 * @param clazz <span class="en-US">Provider implements class</span>
	 *              <span class="zh-CN">适配器实现类</span>
	 * @return <span class="en-US">The name of provider</span>
	 * <span class="zh-CN">适配器名称</span>
	 */
	public static String providerName(@Nonnull final Class<?> clazz) {
		return providerName(clazz, DEFAULT_LANGUAGE_CODE);
	}

	/**
	 * <h3 class="en-US">Get the name of the given adapter implementation class</h3>
	 * <h3 class="zh-CN">获取给定适配器实现类的名称</h3>
	 *
	 * @param clazz        <span class="en-US">Provider implements class</span>
	 *                     <span class="zh-CN">适配器实现类</span>
	 * @param languageCode <span class="en-US">Language code</span>
	 *                     <span class="zh-CN">语言代码</span>
	 * @return <span class="en-US">The name of provider</span>
	 * <span class="zh-CN">适配器名称</span>
	 */
	public static String providerName(@Nonnull final Class<?> clazz, final String languageCode) {
		return Optional.ofNullable(clazz.getAnnotation(Provider.class))
				.filter(provider -> StringUtils.notBlank(provider.titleKey()))
				.map(provider -> newAgent(clazz).findMessage(provider.titleKey(), languageCode))
				.orElse(Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * <h3 class="en-US">Get the description of the given adapter implementation class</h3>
	 * <h3 class="zh-CN">获取给定适配器实现类的简介</h3>
	 *
	 * @param clazz <span class="en-US">Provider implements class</span>
	 *              <span class="zh-CN">适配器实现类</span>
	 * @return <span class="en-US">The name of provider</span>
	 * <span class="zh-CN">适配器名称</span>
	 */
	public static String providerDescription(@Nonnull final Class<?> clazz) {
		return providerDescription(clazz, DEFAULT_LANGUAGE_CODE);
	}

	/**
	 * <h3 class="en-US">Get the description of the given adapter implementation class</h3>
	 * <h3 class="zh-CN">获取给定适配器实现类的简介</h3>
	 *
	 * @param clazz        <span class="en-US">Provider implements class</span>
	 *                     <span class="zh-CN">适配器实现类</span>
	 * @param languageCode <span class="en-US">Language code</span>
	 *                     <span class="zh-CN">语言代码</span>
	 * @return <span class="en-US">The name of provider</span>
	 * <span class="zh-CN">适配器名称</span>
	 */
	public static String providerDescription(@Nonnull final Class<?> clazz, final String languageCode) {
		return Optional.ofNullable(clazz.getAnnotation(Provider.class))
				.filter(provider -> StringUtils.notBlank(provider.descriptionKey()))
				.map(provider -> newAgent(clazz).findMessage(provider.descriptionKey(), languageCode))
				.orElse(Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * <h3 class="en-US">Set enabled language code information</h3>
	 * <h3 class="zh-CN">设置开启的语言代码信息</h3>
	 *
	 * @param languageCodes <span class="en-US">Array of language codes that need to be enabled</span>
	 *                      <span class="zh-CN">需要开启的语言代码数组</span>
	 */
	public static void enableLanguages(@Nonnull final String... languageCodes) {
		ENABLED_LANGUAGES.clear();
		if (CollectionUtils.isEmpty(languageCodes)) {
			ENABLED_LANGUAGES.addAll(REGISTERED_LANGUAGES.keySet());
		} else {
			Arrays.stream(languageCodes)
					.filter(languageCode -> !CollectionUtils.contains(REGISTERED_LANGUAGES.keySet(), languageCode))
					.forEach(ENABLED_LANGUAGES::add);
		}
		if (!CollectionUtils.contains(ENABLED_LANGUAGES, DEFAULT_LANGUAGE_CODE)) {
			ENABLED_LANGUAGES.add(DEFAULT_LANGUAGE_CODE);
		}
	}

	/**
	 * <h3 class="en-US">Turn off language support based on the given parameter languageCode</h3>
	 * <h3 class="zh-CN">根据给定的参数 languageCode 关闭语言支持</h3>
	 *
	 * @param languageCode <span class="en-US">Resource language code</span>
	 *                     <span class="zh-CN">资源语言代码</span>
	 */
	public static void disableLanguage(@Nonnull final String languageCode) {
		if (StringUtils.notBlank(languageCode) && CollectionUtils.contains(ENABLED_LANGUAGES, languageCode)) {
			ENABLED_LANGUAGES.remove(languageCode);
		}
	}

	/**
	 * <h3 class="en-US">Remove bundle resources by given argument bundle if registered.</h3>
	 * <h3 class="zh-CN">根据给定的参数 bundle 移除已注册的国际化信息资源</h3>
	 *
	 * @param groupId <span class="en-US">Resource group id</span>
	 *                <span class="zh-CN">资源的组ID</span>
	 * @param bundle  <span class="en-US">Resource bundle</span>
	 *                <span class="zh-CN">资源的标识</span>
	 */
	public static void removeBundle(@Nonnull final String groupId, @Nonnull final String bundle) {
		if (StringUtils.notBlank(groupId) && StringUtils.notBlank(bundle)) {
			REGISTERED_RESOURCES.remove(groupId + ":" + bundle);
		}
	}

	/**
	 * <h3 class="en-US">Retrieve internationalization information content and formatted by given collections</h3>
	 * <h3 class="zh-CN">读取国际化资源信息详情并使用给定的参数集合格式化资源信息</h3>
	 *
	 * @param identifyKey  <span class="en-US">Resource identified key</span>
	 *                     <span class="zh-CN">资源唯一识别码</span>
	 * @param errorCode    <span class="en-US">Error code</span>
	 *                     <span class="zh-CN">错误代码</span>
	 * @param languageCode <span class="en-US">Resource language code</span>
	 *                     <span class="zh-CN">资源语言代码</span>
	 * @param collections  <span class="en-US">given parameters of information formatter</span>
	 *                     <span class="zh-CN">用于资源信息格式化的参数</span>
	 * @return <span class="en-US">Formatted resource information or joined string by character '/' if not found</span>
	 * <span class="zh-CN">格式化的资源信息，如果未找到则返回使用'/'拼接的字符串</span>
	 */
	private static String findMessage(final String identifyKey, final long errorCode, final String languageCode,
	                                  final Object... collections) {
		if (!CollectionUtils.contains(ENABLED_LANGUAGES, languageCode)
				&& !CollectionUtils.contains(ENABLED_LANGUAGES, DEFAULT_LANGUAGE_CODE)) {
			return identifyKey(Long.toString(errorCode), languageCode);
		}
		if (StringUtils.notBlank(identifyKey) && StringUtils.notBlank(languageCode)) {
			return Optional.ofNullable(REGISTERED_RESOURCES.get(identifyKey))
					.map(messageResource ->
							messageResource.findMessage(errorCode, languageCode, DEFAULT_LANGUAGE_CODE, collections))
					.orElse(identifyKey(Long.toString(errorCode), languageCode));
		}
		return Globals.DEFAULT_VALUE_STRING;
	}

	/**
	 * <h3 class="en-US">Retrieve internationalization information content and formatted by given collections</h3>
	 * <h3 class="zh-CN">读取国际化资源信息详情并使用给定的参数集合格式化资源信息</h3>
	 *
	 * @param identifyKey  <span class="en-US">Resource identified key</span>
	 *                     <span class="zh-CN">资源唯一识别码</span>
	 * @param messageKey   <span class="en-US">Message identify key</span>
	 *                     <span class="zh-CN">信息识别键值</span>
	 * @param languageCode <span class="en-US">Resource language code</span>
	 *                     <span class="zh-CN">资源语言代码</span>
	 * @param collections  <span class="en-US">given parameters of information formatter</span>
	 *                     <span class="zh-CN">用于资源信息格式化的参数</span>
	 * @return <span class="en-US">Formatted resource information or joined string by character '/' if not found</span>
	 * <span class="zh-CN">格式化的资源信息，如果未找到则返回使用'/'拼接的字符串</span>
	 */
	private static String findMessage(final String identifyKey, final String messageKey, final String languageCode,
	                                  final Object... collections) {
		if (!CollectionUtils.contains(ENABLED_LANGUAGES, languageCode)
				&& !CollectionUtils.contains(ENABLED_LANGUAGES, DEFAULT_LANGUAGE_CODE)) {
			return identifyKey(messageKey, languageCode);
		}
		if (StringUtils.notBlank(identifyKey) && StringUtils.notBlank(languageCode)) {
			return Optional.ofNullable(REGISTERED_RESOURCES.get(identifyKey))
					.map(messageResource ->
							messageResource.findMessage(messageKey, languageCode, DEFAULT_LANGUAGE_CODE, collections))
					.filter(StringUtils::notBlank)
					.orElse(identifyKey(messageKey, languageCode));
		}
		return messageKey;
	}

	/**
	 * <h3 class="en-US">Retrieve resource identify key by given class</h3>
	 * <h3 class="zh-CN">根据给定的类查找资源唯一识别码</h3>
	 *
	 * @param messageKey   <span class="en-US">Message identify key</span>
	 *                     <span class="zh-CN">信息识别键值</span>
	 * @param languageCode <span class="en-US">Language code</span>
	 *                     <span class="zh-CN">语言代码</span>
	 */
	public static String identifyKey(final String messageKey, final String languageCode) {
		return messageKey + DEFAULT_SPLIT_CHARACTER + languageCode;
	}

	/**
	 * <h3 class="en-US">Retrieve resource identify key by given class</h3>
	 * <h3 class="zh-CN">根据给定的类查找资源唯一识别码</h3>
	 *
	 * @param clazz <span class="en-US">Class instance</span>
	 *              <span class="zh-CN">类实例对象</span>
	 */
	private static String identifyKey(final Class<?> clazz) {
		String jarPath = URLDecoder.decode(clazz.getProtectionDomain().getCodeSource().getLocation().getFile(),
				Charset.defaultCharset());
		return IDENTIFY_KEY_MAP.getOrDefault(jarPath, Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * <h3 class="en-US">Register i18n message resource</h3>
	 * <h3 class="zh-CN">注册国际化信息资源</h3>
	 *
	 * @param url <span class="en-US">Internationalization resource data URL instance</span>
	 *            <span class="zh-CN">资源数据URL对象</span>
	 */
	private static void registerBundle(final URL url) {
		try {
			BundleResource bundleResource = StringUtils.streamToObject(url.openStream(), BundleResource.class);
			if (bundleResource == null) {
				throw new IOException("Load bundle resource error! ");
			}
			String identifyKey = bundleResource.getGroupId() + ":" + bundleResource.getBundle();
			MessageResource messageResource =
					REGISTERED_RESOURCES.getOrDefault(identifyKey, new MessageResource());
			messageResource.updateResource(bundleResource.getBundleErrors(), bundleResource.getBundleLanguages());
			REGISTERED_RESOURCES.put(identifyKey, messageResource);
			String basePath = url.getPath().substring(0, url.getPath().length() - BUNDLE_RESOURCE_PATH.length());
			if (basePath.startsWith(FileUtils.FILE_URL_PREFIX)) {
				basePath = basePath.substring(FileUtils.FILE_URL_PREFIX.length());
			}
			if (basePath.endsWith(FileUtils.JAR_URL_SEPARATOR)) {
				basePath = basePath.substring(0, basePath.length() - FileUtils.JAR_URL_SEPARATOR.length());
			}
			IDENTIFY_KEY_MAP.put(basePath, identifyKey);
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Group ID: {}, bundle: {}",
						bundleResource.getGroupId(), bundleResource.getBundle());
			}
			messageResource.getRegisteredLanguages()
					.forEach((languageCode, languageName) -> {
						if (!REGISTERED_LANGUAGES.containsKey(languageCode)) {
							REGISTERED_LANGUAGES.put(languageCode, languageName);
						}
					});
		} catch (IOException e) {
			LOGGER.error("Register resource error! Path: {}", url.getPath());
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(Globals.DEFAULT_VALUE_STRING, e);
			}
		}
	}

	/**
	 * <h2 class="en-US">Multilingual Agent</h2>
	 * <h2 class="zh-CN">国际化代理</h2>
	 */
	public static final class Agent {
		/**
		 * <span class="en-US">Resource identified key</span>
		 * <span class="zh-CN">资源唯一识别码</span>
		 */
		private final String identifyKey;

		/**
		 * <h3 class="en-US">Constructor method for MultilingualUtils.Agent</h3>
		 * <h3 class="zh-CN">国际化代理的构造方法</h3>
		 *
		 * @param groupId <span class="en-US">Resource group id</span>
		 *                <span class="zh-CN">资源的组ID</span>
		 * @param bundle  <span class="en-US">Resource bundle</span>
		 *                <span class="zh-CN">资源的标识</span>
		 */
		private Agent(final String groupId, final String bundle) {
			this.identifyKey = groupId + ":" + bundle;
		}

		/**
		 * <h3 class="en-US">Constructor method for MultilingualUtils.Agent</h3>
		 * <h3 class="zh-CN">国际化代理的构造方法</h3>
		 *
		 * @param clazz <span class="en-US">Class instance</span>
		 *              <span class="zh-CN">类实例对象</span>
		 */
		private Agent(final Class<?> clazz) {
			this.identifyKey = MultilingualUtils.identifyKey(clazz);
		}

		/**
		 * <h3 class="en-US">Retrieve internationalization information content and formatted by given collections</h3>
		 * <h3 class="zh-CN">读取国际化资源信息详情并使用给定的参数集合格式化资源信息</h3>
		 *
		 * @param errorCode   <span class="en-US">Error code</span>
		 *                    <span class="zh-CN">错误代码</span>
		 * @param collections <span class="en-US">given parameters of information formatter</span>
		 *                    <span class="zh-CN">用于资源信息格式化的参数</span>
		 * @return <span class="en-US">Formatted resource information or joined string by character '/' if not found</span>
		 * <span class="zh-CN">格式化的资源信息，如果未找到则返回使用'/'拼接的字符串</span>
		 */
		public String errorMessage(final long errorCode, final Object... collections) {
			return this.errorMessage(errorCode, DEFAULT_LANGUAGE_CODE, collections);
		}

		/**
		 * <h3 class="en-US">Retrieve internationalization information content and formatted by given collections</h3>
		 * <h3 class="zh-CN">读取国际化资源信息详情并使用给定的参数集合格式化资源信息</h3>
		 *
		 * @param errorCode    <span class="en-US">Error code</span>
		 *                     <span class="zh-CN">错误代码</span>
		 * @param languageCode <span class="en-US">Language code</span>
		 *                     <span class="zh-CN">语言代码</span>
		 * @param collections  <span class="en-US">given parameters of information formatter</span>
		 *                     <span class="zh-CN">用于资源信息格式化的参数</span>
		 * @return <span class="en-US">Formatted resource information or joined string by character '/' if not found</span>
		 * <span class="zh-CN">格式化的资源信息，如果未找到则返回使用'/'拼接的字符串</span>
		 */
		public String errorMessage(final long errorCode, final String languageCode, final Object... collections) {
			return MultilingualUtils.findMessage(this.identifyKey, errorCode, languageCode, collections);
		}

		/**
		 * <h3 class="en-US">Retrieve internationalization information content and formatted by given collections</h3>
		 * <h3 class="zh-CN">读取国际化资源信息详情并使用给定的参数集合格式化资源信息</h3>
		 *
		 * @param messageKey  <span class="en-US">Message identify key</span>
		 *                    <span class="zh-CN">信息识别键值</span>
		 * @param collections <span class="en-US">given parameters of information formatter</span>
		 *                    <span class="zh-CN">用于资源信息格式化的参数</span>
		 * @return <span class="en-US">Formatted resource information or joined string by character '/' if not found</span>
		 * <span class="zh-CN">格式化的资源信息，如果未找到则返回使用'/'拼接的字符串</span>
		 */
		public String findMessage(final String messageKey, final Object... collections) {
			return MultilingualUtils.findMessage(this.identifyKey, messageKey, DEFAULT_LANGUAGE_CODE, collections);
		}

		/**
		 * <h3 class="en-US">Retrieve internationalization information content and formatted by given collections</h3>
		 * <h3 class="zh-CN">读取国际化资源信息详情并使用给定的参数集合格式化资源信息</h3>
		 *
		 * @param messageKey   <span class="en-US">Message identify key</span>
		 *                     <span class="zh-CN">信息识别键值</span>
		 * @param languageCode <span class="en-US">Language code</span>
		 *                     <span class="zh-CN">语言代码</span>
		 * @param collections  <span class="en-US">given parameters of information formatter</span>
		 *                     <span class="zh-CN">用于资源信息格式化的参数</span>
		 * @return <span class="en-US">Formatted resource information or joined string by character '/' if not found</span>
		 * <span class="zh-CN">格式化的资源信息，如果未找到则返回使用'/'拼接的字符串</span>
		 */
		public String findMessage(final String messageKey, final String languageCode, final Object... collections) {
			return MultilingualUtils.findMessage(this.identifyKey, messageKey, languageCode, collections);
		}

		/**
		 * <h3 class="en-US">Retrieve internationalization information content and formatted by given collections</h3>
		 * <h3 class="zh-CN">读取国际化资源信息详情并使用给定的参数集合格式化资源信息</h3>
		 *
		 * @param messageKey  <span class="en-US">Message identify key</span>
		 *                    <span class="zh-CN">信息识别键值</span>
		 * @param locale      <span class="en-US">locale instance</span>
		 *                    <span class="zh-CN">区域设置实例</span>
		 * @param collections <span class="en-US">given parameters of information formatter</span>
		 *                    <span class="zh-CN">用于资源信息格式化的参数</span>
		 * @return <span class="en-US">Formatted resource information or joined string by character '/' if not found</span>
		 * <span class="zh-CN">格式化的资源信息，如果未找到则返回使用'/'拼接的字符串</span>
		 */
		public String findMessage(final String messageKey, final Locale locale, final Object... collections) {
			return MultilingualUtils.findMessage(this.identifyKey, messageKey, toLanguageCode(locale), collections);
		}
	}
}
