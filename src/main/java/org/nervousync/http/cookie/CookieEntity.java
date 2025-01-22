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
package org.nervousync.http.cookie;

import org.nervousync.commons.Globals;
import org.nervousync.utils.DateTimeUtils;
import org.nervousync.utils.StringUtils;

import java.util.Date;
import java.util.Optional;

/**
 * <h2 class="en-US">Cookie information Define</h2>
 * <h2 class="zh-CN">Cookie信息定义</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 4, 2018 13:01:35 $
 */
public final class CookieEntity {
	/**
	 * <span class="en-US">Cookie name</span>
	 * <span class="zh-CN">Cookie名</span>
	 */
	private String name = null;
	/**
	 * <span class="en-US">Cookie value</span>
	 * <span class="zh-CN">Cookie值</span>
	 */
	private String value = null;
	/**
	 * <span class="en-US">Cookie path</span>
	 * <span class="zh-CN">Cookie目录</span>
	 */
	private String path = null;
	/**
	 * <span class="en-US">Cookie domain name</span>
	 * <span class="zh-CN">Cookie域名</span>
	 */
	private String domain = null;
	/**
	 * <span class="en-US">Cookie expire time</span>
	 * <span class="zh-CN">Cookie过期时间</span>
	 */
	private long expires = Globals.DEFAULT_VALUE_LONG;
	/**
	 * <span class="en-US">Cookie maximum age</span>
	 * <span class="zh-CN">Cookie最大生命周期</span>
	 */
	private long maxAge = Globals.DEFAULT_VALUE_LONG;
	/**
	 * <span class="en-US">Cookie secure status</span>
	 * <span class="zh-CN">Cookie是否用于加密传输</span>
	 */
	private boolean secure = Boolean.FALSE;
	/**
	 * <span class="en-US">Cookie version value</span>
	 * <span class="zh-CN">Cookie版本号</span>
	 */
	private int version = 0;

	/**
	 * <h3 class="en-US">Constructor method for CookieEntity</h3>
	 * <h3 class="zh-CN">CookieEntity构造方法</h3>
	 *
	 * @param cookieValue <span class="en-US">Cookie value from response header</span>
	 *                    <span class="zh-CN">来自响应头的Cookie值</span>
	 */
	public CookieEntity(String cookieValue) {
		if (cookieValue != null && !cookieValue.isEmpty()) {
			String[] cookieItems = StringUtils.delimitedListToStringArray(cookieValue, ";");
			for (String cookieItem : cookieItems) {
				String[] cookieInfo = StringUtils.delimitedListToStringArray(cookieItem, "=");
				if (cookieInfo.length == 2) {
					if ("path".equalsIgnoreCase(cookieInfo[0])) {
						this.path = cookieInfo[1];
					} else if ("domain".equalsIgnoreCase(cookieInfo[0])) {
						this.domain = cookieInfo[1];
					} else if ("expires".equalsIgnoreCase(cookieInfo[0])) {
						this.expires =
								Optional.ofNullable(DateTimeUtils.parseGMTDate(cookieInfo[1]))
										.map(Date::getTime)
										.orElse(Globals.DEFAULT_VALUE_LONG);
					} else if ("max-age".equalsIgnoreCase(cookieInfo[0])) {
						this.maxAge = Long.parseLong(cookieInfo[1]);
					} else if ("version".equalsIgnoreCase(cookieInfo[0])) {
						this.version = Integer.parseInt(cookieInfo[1]);
					} else {
						this.name = cookieInfo[0];
						this.value = cookieInfo[1];
					}
				} else if (cookieInfo.length == 1
						&& "secure".equalsIgnoreCase(cookieInfo[0])) {
					this.secure = true;
				}
			}
		}
	}

	/**
	 * <h3 class="en-US">Getter method for cookie name</h3>
	 * <h3 class="zh-CN">Cookie名的Getter方法</h3>
	 *
	 * @return <span class="en-US">Cookie name</span>
	 * <span class="zh-CN">Cookie名</span>
	 */
	public String getName() {
		return name;
	}

	/**
	 * <h3 class="en-US">Getter method for cookie value</h3>
	 * <h3 class="zh-CN">Cookie值的Getter方法</h3>
	 *
	 * @return <span class="en-US">Cookie value</span>
	 * <span class="zh-CN">Cookie值</span>
	 */
	public String getValue() {
		return value;
	}

	/**
	 * <h3 class="en-US">Getter method for the cookie path</h3>
	 * <h3 class="zh-CN">Cookie目录的Getter方法</h3>
	 *
	 * @return <span class="en-US">Cookie path</span>
	 * <span class="zh-CN">Cookie目录</span>
	 */
	public String getPath() {
		return path;
	}

	/**
	 * <h3 class="en-US">Getter method for cookie domain name</h3>
	 * <h3 class="zh-CN">Cookie域名的Getter方法</h3>
	 *
	 * @return <span class="en-US">Cookie domain name</span>
	 * <span class="zh-CN">Cookie域名</span>
	 */
	public String getDomain() {
		return domain;
	}

	/**
	 * <h3 class="en-US">Getter method for cookie expires</h3>
	 * <h3 class="zh-CN">Cookie过期时间的Getter方法</h3>
	 *
	 * @return <span class="en-US">Cookie expire time</span>
	 * <span class="zh-CN">Cookie过期时间</span>
	 */
	public long getExpires() {
		return expires;
	}

	/**
	 * <h3 class="en-US">Getter method for cookie maximum age</h3>
	 * <h3 class="zh-CN">Cookie最大生命周期的Getter方法</h3>
	 *
	 * @return <span class="en-US">Cookie maximum age</span>
	 * <span class="zh-CN">Cookie最大生命周期</span>
	 */
	public long getMaxAge() {
		return maxAge;
	}

	/**
	 * <h3 class="en-US">Getter method for cookie secure status</h3>
	 * <h3 class="zh-CN">Cookie加密传输的Getter方法</h3>
	 *
	 * @return <span class="en-US">Cookie secure status</span>
	 * <span class="zh-CN">Cookie是否用于加密传输</span>
	 */
	public boolean isSecure() {
		return secure;
	}

	/**
	 * <h3 class="en-US">Getter method for cookie version</h3>
	 * <h3 class="zh-CN">Cookie版本号的Getter方法</h3>
	 *
	 * @return <span class="en-US">Cookie version value</span>
	 * <span class="zh-CN">Cookie版本号</span>
	 */
	public int getVersion() {
		return version;
	}
}
