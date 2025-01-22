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

package org.nervousync.builder;

import org.nervousync.exceptions.builder.BuilderException;

/**
 * <h2 class="en-US">Builder interface</h2>
 * <h2 class="zh-CN">构造器接口</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 4, 2018 16:28:42 $
 */
public interface ParentBuilder {

	/**
	 * <h3 class="en-US">Confirm current configure and return Generics Type instance</h3>
	 * <h3 class="zh-CN">确认当前设置，并返回泛型类实例对象</h3>
	 *
	 * @param object <span class="en-US">Information that needs to be configured</span>
	 *               <span class="zh-CN">需要配置的信息</span>
	 * @throws BuilderException <span class="en-US">If an occurring when confirm current configure</span>
	 *                          <span class="zh-CN">当确认当前配置时时捕获异常</span>
	 */
	void confirm(final Object object) throws BuilderException;

}
