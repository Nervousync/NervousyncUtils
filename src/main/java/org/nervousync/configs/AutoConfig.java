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

package org.nervousync.configs;

import org.nervousync.annotations.configs.Configuration;
import org.nervousync.utils.ReflectionUtils;

import java.util.Optional;

/**
 * <h2 class="en-US">Abstract class of configure file automatically loading</h2>
 * <h2 class="zh-CN">配置文件自动加载的抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Feb 6, 2024 17:10:21 $
 */
public abstract class AutoConfig {

	protected AutoConfig() {
		ConfigureManager configureManager = ConfigureManager.getInstance();
		if (configureManager == null) {
			return;
		}
		ReflectionUtils.getAllDeclaredFields(this.getClass(), Boolean.TRUE)
				.stream()
				.filter(field -> field.isAnnotationPresent(Configuration.class))
				.forEach(field ->
						Optional.ofNullable(field.getAnnotation(Configuration.class))
								.map(configuration ->
										configureManager.readConfigure(field.getType(), configuration.value()))
								.ifPresent(configure -> ReflectionUtils.setField(field, this, configure)));
	}
}
