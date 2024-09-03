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

package org.nervousync.beans.config;

import org.nervousync.annotations.beans.DataTransfer;
import org.nervousync.beans.transfer.AbstractAdapter;
import org.nervousync.commons.Globals;
import org.nervousync.utils.ClassUtils;
import org.nervousync.utils.LoggerUtils;
import org.nervousync.utils.ObjectUtils;
import org.nervousync.utils.StringUtils;

/**
 * <h2 class="en-US">Data convert configure</h2>
 * <h2 class="zh-CN">数据转换配置信息</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Oct 26, 2023 15:12:21 $
 */
public final class TransferConfig {

    /**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
     */
	private final LoggerUtils.Logger logger = LoggerUtils.getLogger(this.getClass());

	/**
	 * <span class="en-US">Converter implementation class must implement the DataConverter interface</span>
	 * <span class="zh-CN">转换器实现类，必须实现DataConverter接口</span>
	 */
	private final AbstractAdapter adapter;

	/**
	 * <h2 class="en-US">Default constructor</h2>
	 * <h2 class="zh-CN">默认构造方法</h2>
	 *
	 * @param transfer <span class="en-US">The annotation of data transfer configure</span>
	 *                 <span class="zh-CN">数据传输配置的注解</span>
	 */
	public TransferConfig(final DataTransfer transfer) {
		if (transfer != null && ClassUtils.isAssignable(AbstractAdapter.class, transfer.adapter())
				&& !ObjectUtils.nullSafeEquals(AbstractAdapter.class, transfer.adapter())) {
			if (StringUtils.isEmpty(transfer.initParam())) {
				this.adapter = ObjectUtils.newInstance(transfer.adapter());
			} else {
				this.adapter = ObjectUtils.newInstance(transfer.adapter(), new Object[]{transfer.initParam()});
			}
		} else {
			this.adapter = null;
		}
	}

	/**
	 * <h3 class="en-US">Convert data to string, when the data to be converted is <code>null</code>, an empty string is returned.</h3>
	 * <h3 class="zh-CN">转换数据为字符串，待转换的数据为<code>null</code>时返回空字符串</h3>
	 *
	 * @param object <span class="en-US">Data to be converted</span>
	 *               <span class="zh-CN">待转换的数据</span>
	 * @return <span class="en-US">Converted string</span>
	 * <span class="zh-CN">转换完成的字符串</span>
	 */
	public String marshal(final Object object) {
		if (object == null || this.adapter == null) {
			return null;
		}

		try {
			return this.adapter.marshal(object);
		} catch (Exception e) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("Stack_Message_Error", e);
			}
			return Globals.DEFAULT_VALUE_STRING;
		}
	}

	/**
	 * <h3 class="en-US">Convert the string to the data of the target object. When the string to be converted is an empty string, <code>null</code> is returned.</h3>
	 * <h3 class="zh-CN">转换字符串为目标对象的数据，待转换的字符串为空字符串时返回<code>null</code></h3>
	 *
	 * @param object <span class="en-US">String to be converted</span>
	 *               <span class="zh-CN">待转换的字符串</span>
	 * @return <span class="en-US">The converted data instance object</span>
	 * <span class="zh-CN">转换完成的数据实例对象</span>
	 */
	public Object unmarshal(final Object object) {
		if (object == null || this.adapter == null) {
			return object;
		}
		try {
			return this.adapter.unmarshal((String) object);
		} catch (Exception e) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("Stack_Message_Error", e);
			}
			return null;
		}
	}
}
