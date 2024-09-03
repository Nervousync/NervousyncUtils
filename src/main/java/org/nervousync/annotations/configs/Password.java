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

package org.nervousync.annotations.configs;

import org.nervousync.security.factory.SecureFactory;

import java.lang.annotation.*;

/**
 * <h2 class="en-US">Annotation for password data</h2>
 * <span class="en-US">
 * The system will automatically enhance the configuration information object.
 * For attributes with this annotation, the system will automatically encrypt and decrypt the data.
 * </span>
 * <h2 class="zh-CN">密码数据的注解</h2>
 * <span class="en-US">系统会自动增强配置信息对象，对于拥有此标注的属性，系统会自动进行数据的加密解密</span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Sep 25, 2022 14:28:27 $
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface Password {

	/**
	 * <span class="en-US">Security configuration name to use when encrypting/decrypting data</span>
	 * <span class="zh-CN">加密/解密数据时使用的安全配置名称</span>
	 *
	 * @return <span class="en-US">Secure config name</span>
	 * <span class="zh-CN">安全配置名称</span>
	 */
	String value() default SecureFactory.SYSTEM_SECURE_NAME;
}
