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

package org.nervousync.test.utils;

import org.junit.jupiter.api.Test;
import org.nervousync.annotations.configs.Password;
import org.nervousync.beans.core.BeanObject;
import org.nervousync.commons.Globals;
import org.nervousync.security.config.SecureSettings;
import org.nervousync.test.BaseTest;
import org.nervousync.utils.ClassUtils;
import org.nervousync.utils.ReflectionUtils;
import org.nervousync.utils.StringUtils;

import java.lang.reflect.ParameterizedType;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public final class ConfigureTest extends BaseTest {

	@Test
	public void test() {
		this.scanFields(SecureSettings.class);
	}

	/**
	 * <h3 class="en-US">Scan name registration key field</h3>
	 * <h3 class="zh-CN">扫描名注册密钥字段</h3>
	 *
	 * @param beanClass <span class="en-US">Data class</span>
	 *                  <span class="zh-CN">数据类</span>
	 */
	private void scanFields(final Class<?> beanClass) {
		if (!ClassUtils.isAssignable(BeanObject.class, beanClass)) {
			return;
		}
		Map<String, String> fieldMap = new HashMap<>();
		ReflectionUtils.getAllDeclaredFields(beanClass)
				.forEach(field -> {
					Class<?> fieldType = field.getType();
					if (fieldType.isArray()) {
						Class<?> checkType = ClassUtils.componentType(fieldType);
						if (ClassUtils.isAssignable(BeanObject.class, checkType)) {
							this.scanFields(checkType);
							fieldMap.put(field.getName(), Globals.DEFAULT_VALUE_STRING);
						}
					} else if (ClassUtils.isAssignable(Collection.class, fieldType)) {
						Class<?> checkType = Optional.of((ParameterizedType) field.getGenericType())
								.map(ParameterizedType::getActualTypeArguments)
								.filter(actualTypeArguments -> actualTypeArguments.length > 0)
								.map(actualTypeArguments -> (Class<?>) actualTypeArguments[0])
								.orElse(null);
						if (ClassUtils.isAssignable(BeanObject.class, checkType)) {
							this.scanFields(checkType);
							fieldMap.put(field.getName(), Globals.DEFAULT_VALUE_STRING);
						}
					} else if (ClassUtils.isAssignable(BeanObject.class, fieldType)) {
						this.scanFields(fieldType);
						fieldMap.put(field.getName(), Globals.DEFAULT_VALUE_STRING);
					} else if (field.isAnnotationPresent(Password.class)) {
						fieldMap.put(field.getName(),
								Optional.ofNullable(field.getAnnotation(Password.class))
										.map(Password::value)
										.filter(StringUtils::notBlank)
										.orElse(Globals.DEFAULT_VALUE_STRING));
					}
				});
		System.out.println(fieldMap);
	}
}
