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

import jakarta.servlet.jsp.JspException;
import jakarta.servlet.jsp.PageContext;

import java.util.HashMap;
import java.util.Map;

public final class TagUtils {

	/**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
	 */
    private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(TagUtils.class);

	private static final Map<String, Integer> SCOPE_MAPS = new HashMap<>();

    static {
		TagUtils.SCOPE_MAPS.put("page", PageContext.PAGE_SCOPE);
		TagUtils.SCOPE_MAPS.put("request", PageContext.REQUEST_SCOPE);
		TagUtils.SCOPE_MAPS.put("session", PageContext.SESSION_SCOPE);
		TagUtils.SCOPE_MAPS.put("application", PageContext.APPLICATION_SCOPE);
    }

	public static int getScope(final String scopeName) throws JspException {
        if (StringUtils.isEmpty(scopeName)) {
            return PageContext.PAGE_SCOPE;
        }
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Scope Name: " + scopeName);
		}
		Integer scope = SCOPE_MAPS.get(scopeName.toLowerCase());

		if (scope == null) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Scope is null");
			}
			throw new JspException("Can't found the scope");
		}

		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Return value: " + scope);
		}

		return scope;
	}
}
