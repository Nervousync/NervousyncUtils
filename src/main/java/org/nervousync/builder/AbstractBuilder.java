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
 * <h2 class="en-US">Abstract builder for Generics Type</h2>
 * <h2 class="zh-CN">拥有父构造器的抽象构造器</h2>
 *
 * @param <T> <span class="en-US">Generics Type Class</span>
 *            <span class="zh-CN">泛型类</span>
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 4, 2018 16:09:54 $
 */
public abstract class AbstractBuilder<T> implements Builder<T> {
	/**
	 * <span class="en-US">Generics Type Class</span>
	 * <span class="zh-CN">泛型类</span>
	 */
	protected final T parentBuilder;

	/**
	 * <h3 class="en-US">Protected constructor for AbstractBuilder</h3>
	 * <h3 class="zh-CN">AbstractBuilder的构造函数</h3>
	 *
	 * @param parentBuilder <span class="en-US">Generics Type instance</span>
	 *                      <span class="zh-CN">泛型类实例对象</span>
	 */
	protected AbstractBuilder(final T parentBuilder) {
		this.parentBuilder = parentBuilder;
	}

	/**
	 * <h3 class="en-US">Protected abstract method for build current configure</h3>
	 * <h3 class="zh-CN">保护的抽象方法，用于构建当前配置信息</h3>
	 *
	 * @throws BuilderException <span class="en-US">If an occurs when build current configure</span>
	 *                          <span class="zh-CN">当构建当前配置时时捕获异常</span>
	 */
	protected abstract void build() throws BuilderException;

	/**
	 * <h3 class="en-US">Confirm current configure and return Generics Type instance</h3>
	 * <h3 class="zh-CN">确认当前设置，并返回泛型类实例对象</h3>
	 *
	 * @return <span class="en-US">Generics Type Class</span>
	 * <span class="zh-CN">泛型类</span>
	 * @throws BuilderException <span class="en-US">If an occurs when confirm current configure</span>
	 *                          <span class="zh-CN">当确认当前配置时时捕获异常</span>
	 */
	@Override
	public final T confirm() throws BuilderException {
		this.build();
		return this.parentBuilder;
	}
}
