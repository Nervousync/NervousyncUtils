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
package org.nervousync.generator.uuid.timer;

/**
 * <h2 class="en-US">Interface of time synchronizer, using for UUID version 2</h2>
 * <h2 class="zh-CN">时间同步器接口，用于UUID版本2</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 06, 2022 12:54:12 $
 */
public interface TimeSynchronizer {
	/**
	 * <h3 class="en-US">Initialize current time synchronizer</h3>
	 * <h3 class="zh-CN">初始化当前时间同步器</h3>
	 *
	 * @return <span class="en-US">Initialize timestamp value</span>
	 * <span class="zh-CN">初始时间戳</span>
	 */
	long initialize();

	/**
	 * <h3 class="en-US">Deactivate current time synchronizer</h3>
	 * <h3 class="zh-CN">反激活当前时间同步器</h3>
	 */
	void deactivate();

	/**
	 * <h3 class="en-US">Update timestamp of current time synchronizer</h3>
	 * <h3 class="zh-CN">更新当前时间同步器的时间戳</h3>
	 *
	 * @param currentTimeMillis <span class="en-US">Update timestamp value</span>
	 *                          <span class="zh-CN">更新时间戳</span>
	 * @return <span class="en-US">Updated timestamp value</span>
	 * <span class="zh-CN">更新的时间戳</span>
	 */
	long update(long currentTimeMillis);

}
