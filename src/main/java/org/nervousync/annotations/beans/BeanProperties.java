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

import java.lang.annotation.*;

/**
 * <h2 class="en-US">Annotation for data mapping targets</h2>
 * <span class="en-US">Mappings for data copy to targets</span>
 * <h2 class="zh-CN">数据复制目标的注解</h2>
 * <span class="en-US">标注用于复制数据到指定的多个目标</span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Sep 25, 2022 14:28:27 $
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface BeanProperties {

	/**
	 * <h3 class="en-US">BeanProperty annotation array</h3>
	 * <h3 class="zh-CN">BeanProperty注解数组</h3>
	 *
	 * @return <span class="en-US">BeanProperty annotation arrays</span>
	 * <span class="zh-CN">BeanProperty注解数组</span>
	 * @see org.nervousync.annotations.beans.BeanProperty
	 */
	BeanProperty[] value();

}
