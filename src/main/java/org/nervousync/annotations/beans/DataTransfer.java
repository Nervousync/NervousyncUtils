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

package org.nervousync.annotations.beans;

import org.nervousync.beans.transfer.AbstractAdapter;
import org.nervousync.commons.Globals;

import java.lang.annotation.*;

/**
 * <h2 class="en-US">The annotation of data transfer configure</h2>
 * <h2 class="zh-CN">数据传输配置的注解</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Ayg 7, 2023 15:32:18 $
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface DataTransfer {

	/**
	 * @return <span class="en-US">Data converter class</span>
	 * <span class="zh-CN">数据转换类</span>
	 */
	Class<? extends AbstractAdapter> adapter() default AbstractAdapter.class;

	/**
	 * @return <span class="en-US">Data conversion class constructor parameters, the default empty string is the parameterless constructor</span>
	 * <span class="zh-CN">数据转换类构造方法参数，默认空字符串为无参构造方法</span>
	 */
	String initParam() default Globals.DEFAULT_VALUE_STRING;
}
