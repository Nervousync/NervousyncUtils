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
import org.nervousync.utils.DateTimeUtils;
import org.nervousync.utils.StringUtils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * <h2 class="en-US">Format UTC timestamp to local time output</h2>
 * <h2 class="zh-CN">格式化UTC时间戳为本地时间输出</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 26, 2023 18:21:49 $
 */
public final class UTCFormatTag extends TagSupport {

	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 3894229344528675001L;

	/**
	 * <span class="en-US">UTC timestamp (unit: milliseconds)</span>
	 * <span class="zh-CN">UTC时间戳（单位：毫秒）</span>
	 */
	private Long utc = Globals.DEFAULT_VALUE_LONG;
	/**
	 * <span class="en-US">Pattern string</span>
	 * <span class="zh-CN">格式字符串</span>
	 */
	private String pattern = Globals.DEFAULT_VALUE_STRING;

	public int doStartTag() throws JspException {
		if (this.utc != null && this.utc > 0L) {
			try {
				JspWriter jspWriter = this.pageContext.getOut();
				LocalDateTime localDateTime = DateTimeUtils.utcToLocal(this.utc);
				if (localDateTime != null) {
					if (StringUtils.isEmpty(this.pattern)) {
						jspWriter.write(localDateTime.toString());
					} else {
						jspWriter.write(localDateTime.format(DateTimeFormatter.ofPattern(this.pattern)));
					}
				}
			} catch (Exception e) {
				throw new JspException(e);
			}
		}
		return SKIP_BODY;
	}

	public Long getUtc() {
		return utc;
	}

	public void setUtc(Long utc) {
		this.utc = utc;
	}

	public String getPattern() {
		return pattern;
	}

	public void setPattern(String pattern) {
		this.pattern = pattern;
	}
}
