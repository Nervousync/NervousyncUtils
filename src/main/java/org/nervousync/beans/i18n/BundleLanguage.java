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

package org.nervousync.beans.i18n;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.nervousync.annotations.beans.OutputConfig;
import org.nervousync.beans.core.BeanObject;
import org.nervousync.utils.StringUtils;

import java.util.List;

/**
 * <h2 class="en-US">Internationalization Language Data</h2>
 * <h2 class="zh-CN">国际化语言数据</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 19, 2023 16:48:39 $
 */
@OutputConfig(type = StringUtils.StringType.JSON)
public final class BundleLanguage extends BeanObject {

	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 8485728786782228020L;

	/**
	 * <span class="en-US">Language code</span>
	 * <span class="zh-CN">语言代码</span>
	 */
	@JsonProperty("code")
	private String languageCode;
	/**
	 * <span class="en-US">Language name</span>
	 * <span class="zh-CN">语言名称</span>
	 */
	@JsonProperty("name")
	private String languageName;
	/**
	 * <span class="en-US">Internationalization Information Data List</span>
	 * <span class="zh-CN">国际化信息数据列表</span>
	 */
	@JsonProperty("messages")
	private List<BundleMessage> bundleMessages;

	/**
	 * <h3 class="en-US">Constructor for internationalization language data</h3>
	 * <h3 class="zh-CN">国际化语言数据的构造方法</h3>
	 */
	public BundleLanguage() {
	}

	/**
	 * <h3 class="en-US">Getter method for language code</h3>
	 * <h3 class="zh-CN">语言代码的Getter方法</h3>
	 *
	 * @return <span class="en-US">Language code</span>
	 * <span class="zh-CN">语言代码</span>
	 */
	public String getLanguageCode() {
		return languageCode;
	}

	/**
	 * <h3 class="en-US">Setter method for language code</h3>
	 * <h3 class="zh-CN">语言代码的Setter方法</h3>
	 *
	 * @param languageCode <span class="en-US">Language code</span>
	 *                     <span class="zh-CN">语言代码</span>
	 */
	public void setLanguageCode(String languageCode) {
		this.languageCode = languageCode;
	}

	/**
	 * <h3 class="en-US">Getter method for language name</h3>
	 * <h3 class="zh-CN">语言名称的Getter方法</h3>
	 *
	 * @return <span class="en-US">Language name</span>
	 * <span class="zh-CN">语言名称</span>
	 */
	public String getLanguageName() {
		return languageName;
	}

	/**
	 * <h3 class="en-US">Setter method for language name</h3>
	 * <h3 class="zh-CN">语言名称的Setter方法</h3>
	 *
	 * @param languageName <span class="en-US">Language name</span>
	 *                     <span class="zh-CN">语言名称</span>
	 */
	public void setLanguageName(String languageName) {
		this.languageName = languageName;
	}

	/**
	 * <h3 class="en-US">Getter method for internationalization information data list</h3>
	 * <h3 class="zh-CN">国际化信息数据列表的Getter方法</h3>
	 *
	 * @return <span class="en-US">Internationalization Information Data List</span>
	 * <span class="zh-CN">国际化信息数据列表</span>
	 */
	public List<BundleMessage> getBundleMessages() {
		return bundleMessages;
	}

	/**
	 * <h3 class="en-US">Setter method for internationalization information data list</h3>
	 * <h3 class="zh-CN">国际化信息数据列表的Setter方法</h3>
	 *
	 * @param bundleMessages <span class="en-US">Internationalization Information Data List</span>
	 *                       <span class="zh-CN">国际化信息数据列表</span>
	 */
	public void setBundleMessages(List<BundleMessage> bundleMessages) {
		this.bundleMessages = bundleMessages;
	}
}
