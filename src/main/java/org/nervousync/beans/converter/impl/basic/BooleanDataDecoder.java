/*
 * Licensed to the Nervousync Studio (NSYC) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
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
package org.nervousync.beans.converter.impl.basic;

import org.nervousync.beans.converter.DataConverter;
import org.nervousync.utils.ClassUtils;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public final class BooleanDataDecoder extends DataConverter {

	@Override
	@SuppressWarnings("unchecked")
	public <T> T convert(final Object object, final Class<T> targetClass) {
		if (object instanceof String) {
			Boolean boolValue = Boolean.valueOf((String) object);
			try {
				if (targetClass.isPrimitive()) {
					String className = targetClass.getName();
					String methodName = className + "Value";
					Method convertMethod = ClassUtils.findMethod(ClassUtils.primitiveWrapper(targetClass),
							methodName, new Class[]{});
					if (convertMethod != null) {
						return (T) convertMethod.invoke(boolValue);
					}
				}
				return targetClass.cast(boolValue);
			} catch (IllegalAccessException | InvocationTargetException ignored) {
			}
		}
		return targetClass.cast(object);
	}
}
