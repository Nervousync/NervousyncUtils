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

package org.nervousync.taglib.logic;

import jakarta.servlet.jsp.tagext.TagSupport;

/**
 * <h2 class="en-US">Abstract class used to determine tags</h2>
 * <h2 class="zh-CN">用于判断标签的抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 26, 2023 19:05:28 $
 */
public abstract class ConditionTag extends TagSupport {

	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 3644280239591305855L;

	@Override
	public final int doStartTag() {
		if (condition()) {
			return EVAL_BODY_INCLUDE;
		} else {
			return SKIP_BODY;
		}
	}

	@Override
	public final int doEndTag() {
		return EVAL_PAGE;
	}

	/**
	 * <h3 class="en-US">Abstract method, used to perform judgment</h3>
	 * <h3 class="zh-CN">抽象方法，用于执行判断</h3>
	 *
	 * @return <span class="en-US">Condition result</span>
	 * <span class="zh-CN">判断结果</span>
	 */
	protected abstract boolean condition();
}
