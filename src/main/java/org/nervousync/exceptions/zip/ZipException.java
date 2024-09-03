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
package org.nervousync.exceptions.zip;

import org.nervousync.commons.Globals;
import org.nervousync.exceptions.AbstractException;

/**
 * <h2 class="en-US">Zip Exception</h2>
 * <h2 class="zh-CN">ZIP异常</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Nov 22, 2017 4:08:31 PM $
 */
public final class ZipException extends AbstractException {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = -4262795571663295796L;

	/**
	 * <h3 class="en-US">Constructor method for ZipException</h3>
	 * <span class="en-US">Create a new ZipException with the specified message.</span>
	 * <h3 class="zh-CN">ZipException构造方法</h3>
	 * <span class="zh-CN">使用特定的信息创建ZipException实例对象。</span>
	 *
	 * @param msg <span class="en-US">The specified message</span>
	 *            <span class="zh-CN">特定的信息</span>
	 */
//	 * @param errorCode 	<span class="en-US">Error identified code</span>
//     *                      <span class="zh-CN">错误识别代码</span>
	public ZipException(final String msg) {
		super(Globals.DEFAULT_VALUE_INT, "", msg);
	}

	/**
	 * <h3 class="en-US">Constructor method for ZipException</h3>
	 * <span class="en-US">Create a new ZipException with the specified message.</span>
	 * <h3 class="zh-CN">ZipException构造方法</h3>
	 * <span class="zh-CN">使用特定的信息创建ZipException实例对象。</span>
	 *
	 * @param msg   <span class="en-US">The specified message</span>
	 *              <span class="zh-CN">特定的信息</span>
	 * @param cause <span class="en-US">The root cause</span>
	 *              <span class="zh-CN">异常信息对象实例</span>
	 */
//	 * @param errorCode 	<span class="en-US">Error identified code</span>
//     *                      <span class="zh-CN">错误识别代码</span>
	public ZipException(final String msg, final Throwable cause) {
		super(Globals.DEFAULT_VALUE_INT, "", msg, cause);
	}

	/**
	 * <h3 class="en-US">Constructor method for ZipException</h3>
	 * <span class="en-US">Create a new ZipException with the specified message.</span>
	 * <h3 class="zh-CN">ZipException构造方法</h3>
	 * <span class="zh-CN">使用特定的信息创建ZipException实例对象。</span>
	 *
	 * @param errorCode   <span class="en-US">Error identified code</span>
	 *                    <span class="zh-CN">错误识别代码</span>
	 * @param collections <span class="en-US">given parameters of information formatter</span>
	 *                    <span class="zh-CN">用于资源信息格式化的参数</span>
	 */
	public ZipException(final long errorCode, final Object... collections) {
		super(errorCode, collections);
	}

	/**
	 * <h3 class="en-US">Constructor method for ZipException</h3>
	 * <span class="en-US">Create a new ZipException with the specified message and root cause.</span>
	 * <h3 class="zh-CN">ZipException构造方法</h3>
	 * <span class="zh-CN">使用特定的信息以及异常信息对象实例创建ZipException实例对象。</span>
	 *
	 * @param errorCode   <span class="en-US">Error identified code</span>
	 *                    <span class="zh-CN">错误识别代码</span>
	 * @param cause       <span class="en-US">The root cause</span>
	 *                    <span class="zh-CN">异常信息对象实例</span>
	 * @param collections <span class="en-US">given parameters of information formatter</span>
	 *                    <span class="zh-CN">用于资源信息格式化的参数</span>
	 */
	public ZipException(final long errorCode, final Throwable cause, final Object... collections) {
		super(errorCode, cause, collections);
	}
}
