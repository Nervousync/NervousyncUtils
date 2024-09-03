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

package org.nervousync.taglib.bean;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.jsp.tagext.TagSupport;
import org.nervousync.commons.Globals;
import org.nervousync.utils.StringUtils;

/**
 * <h2 class="en-US">Set property value</h2>
 * <h2 class="zh-CN">设置属性值</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 26, 2023 18:26:33 $
 */
public final class AttributeTag extends TagSupport {

	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 8562690095965761722L;
	/**
	 * <span class="en-US">Property name, if this value is null or empty string, the value of id is used</span>
	 * <span class="zh-CN">属性名称，如果此值为null或空字符串，则使用id的值</span>
	 */
	private String name = Globals.DEFAULT_VALUE_STRING;
	/**
	 * <span class="en-US">set attribute value</span>
	 * <span class="zh-CN">设置的属性值</span>
	 */
	private Object value = null;

	@Override
	public int doStartTag() {
		if (this.value != null) {
			HttpServletRequest request = (HttpServletRequest) this.pageContext.getRequest();
			String attributeName = StringUtils.isEmpty(this.name) ? this.id : this.name;
			if (StringUtils.notBlank(attributeName)) {
				request.setAttribute(attributeName, this.value);
			}
		}
		return SKIP_BODY;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Object getValue() {
		return value;
	}

	public void setValue(Object value) {
		this.value = value;
	}
}
