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
package org.nervousync.generator;

/**
 * <h2 class="en-US">Interface class of ID generator</h2>
 * <h2 class="zh-CN">ID生成器的接口</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 06, 2022 12:37:26 $
 */
public interface IGenerator<T> {
	/**
	 * <h3 class="en-US">Generate ID value</h3>
	 * <h3 class="zh-CN">生成ID值</h3>
	 *
	 * @return <span class="en-US">Generated value</span>
	 * <span class="zh-CN">生成的ID值</span>
	 */
	T generate();

	/**
	 * <h3 class="en-US">Generate ID value using given parameter</h3>
	 * <h3 class="zh-CN">使用给定的参数生成ID值</h3>
	 *
	 * @param dataBytes <span class="en-US">Given parameter</span>
	 *                  <span class="zh-CN">给定的参数</span>
	 * @return <span class="en-US">Generated value</span>
	 * <span class="zh-CN">生成的ID值</span>
	 */
	T generate(byte[] dataBytes);

	/**
	 * <h3 class="en-US">Destroy current generator instance</h3>
	 * <h3 class="zh-CN">销毁当前生成器实例对象</h3>
	 */
	void destroy();
}
