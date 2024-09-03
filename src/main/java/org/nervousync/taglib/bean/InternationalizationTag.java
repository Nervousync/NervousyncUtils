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

import jakarta.servlet.jsp.JspException;
import jakarta.servlet.jsp.JspWriter;
import jakarta.servlet.jsp.tagext.TagSupport;
import org.nervousync.commons.Globals;
import org.nervousync.utils.MultilingualUtils;
import org.nervousync.utils.StringUtils;

/**
 * <h2 class="en-US">International information output</h2>
 * <h2 class="zh-CN">国际化信息输出</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 26, 2023 18:32:15 $
 */
public final class InternationalizationTag extends TagSupport {

	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 5675850269122084655L;

	/**
	 * <span class="en-US">Resource group id</span>
	 * <span class="zh-CN">资源的组ID</span>
	 */
	private String groupId = Globals.DEFAULT_VALUE_STRING;
	/**
	 * <span class="en-US">Resource bundle</span>
	 * <span class="zh-CN">资源的标识</span>
	 */
	private String bundle = Globals.DEFAULT_VALUE_STRING;
	/**
	 * <span class="en-US">Message identify key</span>
	 * <span class="zh-CN">信息识别键值</span>
	 */
	private String key = Globals.DEFAULT_VALUE_STRING;

	public int doStartTag() throws JspException {
		if (StringUtils.notBlank(this.groupId) && StringUtils.notBlank(this.bundle) || StringUtils.notBlank(this.key)) {
			try {
				JspWriter jspWriter = this.pageContext.getOut();
				jspWriter.write(MultilingualUtils.newAgent(this.groupId, this.bundle)
						.findMessage(this.key, this.pageContext.getRequest().getLocale()));
			} catch (Exception e) {
				throw new JspException(e);
			}
		}
		return SKIP_BODY;
	}

	public String getGroupId() {
		return groupId;
	}

	public void setGroupId(String groupId) {
		this.groupId = groupId;
	}

	public String getBundle() {
		return bundle;
	}

	public void setBundle(String bundle) {
		this.bundle = bundle;
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}
}
