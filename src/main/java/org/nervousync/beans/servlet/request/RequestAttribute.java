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
package org.nervousync.beans.servlet.request;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import jakarta.annotation.Nonnull;
import jakarta.servlet.http.HttpServletRequest;

/**
 * <h2 class="en-US">Parsed request attributes from HttpServletRequest</h2>
 * <h2 class="zh-CN">从HttpServletRequest实例对象解析的属性信息</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.0 $ $Date: Aug 06, 2018 08:56:50 $
 */
public final class RequestAttribute {
	/**
	 * <span class="en-US">Session ID of current request</span>
	 * <span class="zh-CN">当前请求的会话ID</span>
	 */
	private final String sessionId;
	/**
	 * <span class="en-US">Attributes map of current request</span>
	 * <span class="zh-CN">当前请求包含的属性映射</span>
	 */
	private final Map<String, Object> attributeMap;

	/**
	 * <h3 class="en-US">Constructor for RequestAttribute</h3>
	 * <p class="en-US">
	 * Parse given HttpServletRequest instance, read session id,
	 * all exists attributes and put attributes key-value map into field attributeMap
	 * </p>
	 * <h3 class="zh-CN">RequestAttribute的构造方法</h3>
	 * <p class="zh-CN">解析给定的HttpServletRequest实例对象，读取会话ID，将所有存在的属性键值对放入attributeMap</p>
	 *
	 * @param request <span class="en-US">HttpServletRequest instance, must not be null</span>
	 *                <span class="en-US">HttpServletRequest实例对象，不允许为null</span>
	 */
	public RequestAttribute(@Nonnull final HttpServletRequest request) {
		this.sessionId = request.getSession().getId();
		this.attributeMap = new HashMap<>();

		Enumeration<String> e = request.getAttributeNames();

		while (e.hasMoreElements()) {
			String name = e.nextElement();
			this.attributeMap.put(name, request.getAttribute(name));
		}
	}

	/**
	 * <h3 class="en-US">Getter method for Session ID</h3>
	 * <h3 class="zh-CN">会话ID的Getter方法</h3>
	 */
	public String getSessionId() {
		return sessionId;
	}

	/**
	 * <h3 class="en-US">Getter method for attribute map</h3>
	 * <h3 class="zh-CN">属性键值映射表的Getter方法</h3>
	 */
	public Map<String, Object> getAttributeMap() {
		return attributeMap;
	}
}
