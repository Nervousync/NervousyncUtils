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

import org.nervousync.commons.Globals;

/**
 * <h2 class="en-US">ForEach tag for iterating over data</h2>
 * <h2 class="zh-CN">用于遍历数据的ForEach标签</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 26, 2023 19:03:10 $
 */
public final class ForEachTag extends CollectionTag {

	private Integer begin;

	private Integer end;

	private Integer step;

	@Override
	protected int startIndex() {
		return (this.begin == null || this.begin < Globals.INITIALIZE_INT_VALUE)
				? Globals.INITIALIZE_INT_VALUE : this.begin;
	}

	@Override
	protected int endIndex() {
		return (this.end == null || this.end <= Globals.INITIALIZE_INT_VALUE)
				? Globals.DEFAULT_VALUE_INT : this.end;
	}

	@Override
	protected int step() {
		return (this.step == null || this.step <= Globals.INITIALIZE_INT_VALUE)
				? Globals.DEFAULT_STEP_VALUE : this.step;
	}

	public Integer getBegin() {
		return begin;
	}

	public void setBegin(Integer begin) {
		this.begin = begin;
	}

	public Integer getEnd() {
		return end;
	}

	public void setEnd(Integer end) {
		this.end = end;
	}

	public Integer getStep() {
		return step;
	}

	public void setStep(Integer step) {
		this.step = step;
	}
}
