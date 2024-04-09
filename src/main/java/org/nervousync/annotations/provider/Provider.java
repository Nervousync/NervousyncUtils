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

package org.nervousync.annotations.provider;

import org.nervousync.commons.Globals;

import java.lang.annotation.*;

/**
 * <h2 class="en-US">Universal Adapter Annotation</h2>
 * <h2 class="zh-CN">通用适配器注解</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 10, 2021 15:24:26 $
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
public @interface Provider {

    /**
     * <span class="en-US">Provider identification code</span>
     * <span class="zh-CN">适配器识别代码</span>
     *
     * @return  <span class="en-US">Identification code</span>
     *          <span class="zh-CN">识别代码</span>
     */
    String name();

	/**
	 * @return <span class="en">Sort code</span>
	 * <span class="zh-CN">排序代码</span>
	 */
    int sortCode() default Globals.DEFAULT_VALUE_INT;

    /**
     * <span class="en-US">Multilingual key value for provider name</span>
     * <span class="zh-CN">适配器名称的多语言键值</span>
     *
     * @return  <span class="en-US">Multilingual key value</span>
     *          <span class="zh-CN">多语言键值</span>
     */
    String titleKey();

    /**
     * <span class="en-US">Multilingual key value for provider description</span>
     * <span class="zh-CN">适配器简介的多语言键值</span>
     *
     * @return  <span class="en-US">Multilingual key value</span>
     *          <span class="zh-CN">多语言键值</span>
     */
    String descriptionKey() default Globals.DEFAULT_VALUE_STRING;
}
