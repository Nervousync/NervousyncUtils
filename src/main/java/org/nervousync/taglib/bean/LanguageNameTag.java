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
import org.nervousync.utils.MultilingualUtils;
import org.nervousync.utils.StringUtils;

/**
 * <h2 class="en-US">Language name output</h2>
 * <h2 class="zh-CN">语言名称输出</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 26, 2023 18:34:06 $
 */
public final class LanguageNameTag extends TagSupport {

	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = -7898383280969357670L;

	/**
	 * <span class="en-US">Language code</span>
	 * <span class="zh-CN">语言代码</span>
	 */
	private String code;

	public int doStartTag() throws JspException {
		if (StringUtils.notBlank(this.code)) {
			try {
				JspWriter jspWriter = this.pageContext.getOut();
				jspWriter.write(MultilingualUtils.languageName(this.code));
			} catch (Exception e) {
				throw new JspException(e);
			}
		}
		return SKIP_BODY;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}
}
