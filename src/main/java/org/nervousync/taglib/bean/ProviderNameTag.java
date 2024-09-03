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
import org.nervousync.utils.ClassUtils;
import org.nervousync.utils.MultilingualUtils;
import org.nervousync.utils.StringUtils;

/**
 * <h2 class="en-US">Provider name output</h2>
 * <h2 class="zh-CN">适配器名称输出</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 26, 2023 18:40:12 $
 */
public final class ProviderNameTag extends TagSupport {

	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 2391901343255802868L;
	/**
	 * <span class="en-US">Provider implements class name</span>
	 * <span class="zh-CN">适配器实现类名</span>
	 */
	private String className = Globals.DEFAULT_VALUE_STRING;

	public int doStartTag() throws JspException {
		if (StringUtils.notBlank(this.className)) {
			try {
				JspWriter jspWriter = this.pageContext.getOut();
				jspWriter.write(MultilingualUtils.providerName(ClassUtils.forName(this.className),
						MultilingualUtils.toLanguageCode(this.pageContext.getRequest().getLocale())));
			} catch (Exception e) {
				throw new JspException(e);
			}
		}
		return SKIP_BODY;
	}

	public String getClassName() {
		return className;
	}

	public void setClassName(String className) {
		this.className = className;
	}
}
