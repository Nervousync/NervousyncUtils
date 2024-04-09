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
package org.nervousync.exceptions;

import org.nervousync.commons.Globals;
import org.nervousync.utils.MultilingualUtils;
import org.nervousync.utils.ObjectUtils;

/**
 * <h2 class="en-US">Abstract Exception</h2>
 * <h2 class="zh-CN">异常抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 06, 2023 12:56:26 $
 */
public abstract class AbstractException extends Exception {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 3698481050554660066L;
	/**
	 * <span class="en-US">Internationalization information agent</span>
	 * <span class="zh-CN">国际化信息代理</span>
	 */
	private final MultilingualUtils.Agent multiAgent = MultilingualUtils.newAgent(this.getClass());
	/**
	 * <span class="en-US">Error identified code</span>
	 * <span class="zh-CN">错误识别代码</span>
	 */
	private final long errorCode;
	/**
	 * <span class="en-US">Details message of error</span>
	 * <span class="zh-CN">错误详细信息</span>
	 */
	private final String detailMessage;

	/**
	 * <h3 class="en-US">Constructor method for NetworkInfoException</h3>
	 * <span class="en-US">Create a new NetworkInfoException with the specified message.</span>
	 * <h3 class="zh-CN">NetworkInfoException构造方法</h3>
	 * <span class="zh-CN">使用特定的信息创建NetworkInfoException实例对象。</span>
	 *
	 * @param errorCode   <span class="en-US">Error identified code</span>
	 *                    <span class="zh-CN">错误识别代码</span>
	 * @param collections <span class="en-US">given parameters of information formatter</span>
	 *                    <span class="zh-CN">用于资源信息格式化的参数</span>
	 */
	protected AbstractException(final long errorCode, final Object... collections) {
		super(Globals.DEFAULT_VALUE_STRING);
		this.errorCode = errorCode;
		this.detailMessage = this.multiAgent.errorMessage(errorCode, collections);
	}

	/**
	 * <h3 class="en-US">Constructor method for NetworkInfoException</h3>
	 * <span class="en-US">Create a new NetworkInfoException with the specified message and root cause.</span>
	 * <h3 class="zh-CN">NetworkInfoException构造方法</h3>
	 * <span class="zh-CN">使用特定的信息以及异常信息对象实例创建NetworkInfoException实例对象。</span>
	 *
	 * @param errorCode   <span class="en-US">Error identified code</span>
	 *                    <span class="zh-CN">错误识别代码</span>
	 * @param cause       <span class="en-US">The root cause</span>
	 *                    <span class="zh-CN">异常信息对象实例</span>
	 * @param collections <span class="en-US">given parameters of information formatter</span>
	 *                    <span class="zh-CN">用于资源信息格式化的参数</span>
	 */
	protected AbstractException(final long errorCode, final Throwable cause, final Object... collections) {
		super(Globals.DEFAULT_VALUE_STRING, cause);
		this.errorCode = errorCode;
		this.detailMessage = this.multiAgent.errorMessage(errorCode, collections);
	}

	/**
	 * <h3 class="en-US">Getter method for error identified code</h3>
	 * <h3 class="zh-CN">错误识别代码的Getter方法</h3>
	 *
	 * @return <span class="en-US">Error identified code</span>
	 * <span class="zh-CN">错误识别代码</span>
	 */
	public long getErrorCode() {
		return errorCode;
	}

	@Override
	public final String getMessage() {
		return detailMessage;
	}

	/**
	 * (non-javadoc)
	 *
	 * @see Object#equals(Object)
	 */
	@Override
	public final boolean equals(final Object other) {
		if (other == null) {
			return Boolean.FALSE;
		}
		if (this == other) {
			return Boolean.TRUE;
		}
		if (ObjectUtils.nullSafeEquals(other.getClass(), this.getClass())) {
			AbstractException otherBe = (AbstractException) other;
			return (this.errorCode == otherBe.getErrorCode()
					&& ObjectUtils.nullSafeEquals(this.getMessage(), otherBe.getMessage())
					&& ObjectUtils.nullSafeEquals(this.getCause(), otherBe.getCause()));
		}
		return Boolean.FALSE;
	}

	/**
	 * (non-javadoc)
	 *
	 * @see Object#hashCode()
	 */
	@Override
	public final int hashCode() {
		return this.getMessage().hashCode();
	}
}
