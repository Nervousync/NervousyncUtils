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
package org.nervousync.utils;

import org.nervousync.annotations.beans.BeanProperties;
import org.nervousync.annotations.beans.BeanProperty;
import org.nervousync.beans.config.TransferConfig;

import java.lang.reflect.Field;
import java.util.*;

/**
 * <h2 class="en-US">JavaBean Utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Copy object fields value from source object to target object-based field name</ul>
 *     <ul>Copy object fields value from the source object array to target object based annotation: BeanProperty</ul>
 *     <ul>Copy object fields value from source object to target object arrays based annotation: BeanProperty</ul>
 * </span>
 * <h2 class="zh-CN">JavaBean工具集</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>根据属性名称从源数据对象复制数据到目标数据对象</ul>
 *     <ul>根据BeanProperty注解从源数据对象数组复制数据到目标数据对象</ul>
 *     <ul>根据BeanProperty注解从源数据对象复制数据到目标数据对象数组</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Jun 25, 2015 14:55:15 $
 */
public final class BeanUtils {
	/**
	 * <span class="en-US">Multilingual supported logger instance</span>
	 * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(BeanUtils.class);
	/**
	 * <span class="en-US">Registered JavaBean mappings</span>
	 * <span class="zh-CN">已注册的JavaBean映射</span>
	 */
	private static final Map<String, BeanMapping> BEAN_CONFIG_MAP = new HashMap<>();

	/**
	 * <h3 class="en-US">Private constructor for BeanUtils</h3>
	 * <h3 class="zh-CN">JavaBean工具集的私有构造函数</h3>
	 */
	private BeanUtils() {
	}

	/**
	 * <h3 class="en-US">Remove registered JavaBean class</h3>
	 * <h3 class="zh-CN">移除已注册的JavaBean类映射</h3>
	 *
	 * @param classes <span class="en-US">Want removed JavaBean class array</span>
	 *                <span class="zh-CN">需要移除的JavaBean类数组</span>
	 */
	public static void removeBeanConfig(final Class<?>... classes) {
		Arrays.asList(classes).forEach(clazz -> BEAN_CONFIG_MAP.remove(ClassUtils.originalClassName(clazz)));
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Register_Bean_Config_Count_Debug", BEAN_CONFIG_MAP.size());
		}
	}

	/**
	 * <h3 class="en-US">Copy the property values from the source object to the target object, based field name</h3>
	 * <h3 class="zh-CN">从源数据对象复制数据到目标对象，复制依据属性名称</h3>
	 *
	 * @param sourceObject <span class="en-US">Source object instance</span>
	 *                     <span class="zh-CN">源数据对象</span>
	 * @param targetObject <span class="en-US">Target object instance</span>
	 *                     <span class="zh-CN">目标数据对象</span>
	 */
	public static void copyData(final Object sourceObject, final Object targetObject) {
		ReflectionUtils.getAllDeclaredFields(sourceObject.getClass(), Boolean.TRUE)
				.forEach(field ->
						Optional.ofNullable(ReflectionUtils.getFieldValue(field, sourceObject))
								.ifPresent(fieldValue ->
										ReflectionUtils.setField(field.getName(), targetObject, fieldValue)));
	}

	/**
	 * <h3 class="en-US">Copy the map values into the target JavaBean instance</h3>
	 * <p class="en-US">Data mapping to JavaBean field identified by map key</p>
	 * <h3 class="zh-CN">复制Map中的值到目标JavaBean实例</h3>
	 * <p class="zh-CN">数据使用Map的键值映射到JavaBean属性</p>
	 *
	 * @param originalMap  <span class="en-US">Original data map</span>
	 *                     <span class="zh-CN">来源数据Map</span>
	 * @param targetObject <span class="en-US">Target JavaBean instance</span>
	 *                     <span class="zh-CN">目标JavaBean实例</span>
	 */
	public static void copyData(final Map<String, Object> originalMap, final Object targetObject) {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("Data_Map_Debug",
					StringUtils.objectToString(originalMap, StringUtils.StringType.JSON, Boolean.TRUE));
		}
		checkRegister(targetObject.getClass());
		Optional.ofNullable(BEAN_CONFIG_MAP.get(ClassUtils.originalClassName(targetObject.getClass())))
				.ifPresent(beanMapping -> beanMapping.copyData(targetObject, originalMap));
	}

	/**
	 * <h3 class="en-US">Copy the property values of the given source bean arrays into the target bean</h3>
	 * <p class="en-US">Data mapping by field annotated with org.nervousync.annotations.beans.BeanProperty</p>
	 * <h3 class="zh-CN">从给定的JavaBean对象数组复制映射的属性值到目标对象</h3>
	 * <p class="en-US">数据映射配置于使用org.nervousync.annotations.beans.BeanProperty注解的属性</p>
	 *
	 * @param targetObject    <span class="en-US">Target JavaBean instance</span>
	 *                        <span class="zh-CN">目标JavaBean实例</span>
	 * @param originalObjects <span class="en-US">Original JavaBean instance array</span>
	 *                        <span class="zh-CN">数据源JavaBean实例数组</span>
	 */
	public static void copyFrom(final Object targetObject, final Object... originalObjects) {
		if (targetObject == null || originalObjects.length == 0) {
			return;
		}
		checkRegister(targetObject.getClass());
		Optional.ofNullable(BEAN_CONFIG_MAP.get(ClassUtils.originalClassName(targetObject.getClass())))
				.ifPresent(beanMapping -> beanMapping.unmarshall(targetObject, originalObjects));
	}

	/**
	 * <h3 class="en-US">Copy the property values into the given target JavaBean instance arrays</h3>
	 * <p class="en-US">Data mapping by field annotated with org.nervousync.annotations.beans.Mappings</p>
	 * <h3 class="zh-CN">从源对象复制属性值到给定的JavaBean对象数组</h3>
	 * <p class="en-US">数据映射配置于使用org.nervousync.annotations.beans.Mappings注解的属性</p>
	 *
	 * @param originalObject <span class="en-US">Original JavaBean instance</span>
	 *                       <span class="zh-CN">数据源JavaBean实例</span>
	 * @param targetObjects  <span class="en-US">Target JavaBean instance array</span>
	 *                       <span class="zh-CN">目标JavaBean实例数组</span>
	 */
	public static void copyTo(final Object originalObject, final Object... targetObjects) {
		if (originalObject == null || targetObjects.length == 0) {
			return;
		}
		checkRegister(originalObject.getClass());
		Optional.ofNullable(BEAN_CONFIG_MAP.get(ClassUtils.originalClassName(originalObject.getClass())))
				.ifPresent(beanMapping -> beanMapping.marshall(originalObject, targetObjects));
	}

	/**
	 * <h3 class="en-US">Check and register JavaBean mapping configs</h3>
	 * <p class="en-US">
	 *     If given JavaBean class instance not registered,
	 *     generate BeanMapping instance and register the given JavaBean class mapping configured
	 * </p>
	 * <h3 class="zh-CN">检查并注册JavaBean映射配置</h3>
	 * <p class="en-US">如果给定的JavaBean类没有注册映射配置，则生成映射配置对象，并执行注册</p>
	 *
	 * @param clazz <span class="en-US">Given JavaBean class instance</span>
	 *              <span class="zh-CN">给定的JavaBean类对象</span>
	 */
	private static void checkRegister(final Class<?> clazz) {
		Optional.of(ClassUtils.originalClassName(clazz))
				.filter(StringUtils::notBlank)
				.filter(className -> !BEAN_CONFIG_MAP.containsKey(className))
				.ifPresent(className -> BEAN_CONFIG_MAP.put(className, new BeanMapping(clazz)));
	}

	/**
	 * <h2 class="en-US">JavaBean mapping configure define</h2>
	 * <p class="en-US">Private inner class for define JavaBean mapping configure</p>
	 * <h2 class="zh-CN">JavaBean映射配置定义</h2>
	 * <p class="zh-CN">定义JavaBean映射配置的私有内部类</p>
	 */
	private static final class BeanMapping {
		/**
		 * <span class="en-US">JavaBean field mapping configure list</span>
		 * <span class="zh-CN">JavaBean属性映射配置列表</span>
		 */
		private final List<FieldMapping> fieldMappings;

		/**
		 * <h3 class="en-US">Constructor for parse given JavaBean class instance and generate BeanMapping instance</h3>
		 * <h3 class="zh-CN">构造方法用于解析给定的JavaBean类对象，并生成BeanMapping对象</h3>
		 *
		 * @param beanClass <span class="en-US">Given JavaBean class instance</span>
		 *                  <span class="zh-CN">给定的JavaBean类对象</span>
		 */
		BeanMapping(final Class<?> beanClass) {
			this.fieldMappings = new ArrayList<>();
			ReflectionUtils.getAllDeclaredFields(beanClass, Boolean.TRUE)
					.forEach(field -> this.fieldMappings.add(new FieldMapping(field)));
		}

		/**
		 * <h3 class="en-US">Copy property value from the data map</h3>
		 * <h3 class="zh-CN">从数据Map复制属性数据</h3>
		 *
		 * @param targetObject <span class="en-US">Target JavaBean instance</span>
		 *                     <span class="zh-CN">目标JavaBean实例</span>
		 * @param originalMap  <span class="en-US">Original data map</span>
		 *                     <span class="zh-CN">来源数据Map</span>
		 */
		void copyData(final Object targetObject, final Map<String, Object> originalMap) {
			this.fieldMappings.forEach(fieldMapping -> fieldMapping.copyData(targetObject, originalMap));
		}

		/**
		 * <h3 class="en-US">Copy the property values from JavaBean instance arrays to the target JavaBean instance</h3>
		 * <h3 class="zh-CN">从JavaBean实例对象数组复制数据到目标JavaBean实例对象</h3>
		 *
		 * @param object  <span class="en-US">JavaBean instance</span>
		 *                <span class="zh-CN">JavaBean实例</span>
		 * @param objects <span class="en-US">JavaBean instance array</span>
		 *                <span class="zh-CN">JavaBean实例数组</span>
		 */
		void unmarshall(final Object object, final Object... objects) {
			this.fieldMappings.forEach(fieldMapping -> fieldMapping.unmarshall(object, objects));
		}

		/**
		 * <h3 class="en-US">Copy the property values from the JavaBean instance to JavaBean instance arrays</h3>
		 * <h3 class="zh-CN">在JavaBean实例对象复制数据到JavaBean实例对象数组</h3>
		 *
		 * @param object  <span class="en-US">JavaBean instance</span>
		 *                <span class="zh-CN">JavaBean实例</span>
		 * @param objects <span class="en-US">JavaBean instance array</span>
		 *                <span class="zh-CN">JavaBean实例数组</span>
		 */
		void marshall(final Object object, final Object... objects) {
			this.fieldMappings.forEach(fieldMapping -> fieldMapping.marshall(object, objects));
		}
	}

	/**
	 * <h2 class="en-US">JavaBean field mapping configure define</h2>
	 * <p class="en-US">Private inner class for define JavaBean field mapping configure</p>
	 * <h2 class="zh-CN">JavaBean属性映射配置定义</h2>
	 * <p class="zh-CN">定义JavaBean属性映射配置的私有内部类</p>
	 */
	private static final class FieldMapping {
		/**
		 * <span class="en-US">JavaBean field name</span>
		 * <span class="zh-CN">JavaBean属性名</span>
		 */
		private final String fieldName;
		/**
		 * <span class="en-US">JavaBean field type</span>
		 * <span class="zh-CN">JavaBean属性类型</span>
		 */
		private final Class<?> fieldType;
		/**
		 * <span class="en-US">JavaBean field data mapping configure</span>
		 * <span class="zh-CN">JavaBean属性数据映射配置</span>
		 */
		private final List<PropertyMapping> propertyMappings;

		/**
		 * <h3 class="en-US">Constructor for parse given JavaBean field instance and generate FieldMapping instance</h3>
		 * <h3 class="zh-CN">构造方法用于解析给定的JavaBean属性对象，并生成FieldMapping对象</h3>
		 *
		 * @param field <span class="en-US">JavaBean field instance</span>
		 *              <span class="zh-CN">JavaBean类属性对象</span>
		 */
		FieldMapping(final Field field) {
			this.fieldName = field.getName();
			this.fieldType = field.getType();
			this.propertyMappings = new ArrayList<>();
			Arrays.asList(field.getAnnotationsByType(BeanProperty.class)).forEach(this::registerProperty);
			Optional.ofNullable(field.getAnnotation(BeanProperties.class))
					.map(beanProperties -> Arrays.asList(beanProperties.value()))
					.ifPresent(beanProperties -> beanProperties.forEach(this::registerProperty));
			this.propertyMappings.sort((o1, o2) -> o2.compare(o1));
		}

		/**
		 * <h3 class="en-US">Copy property value from the data map</h3>
		 * <h3 class="zh-CN">从数据Map复制属性数据</h3>
		 *
		 * @param targetObject <span class="en-US">Target JavaBean instance</span>
		 *                     <span class="zh-CN">目标JavaBean实例</span>
		 * @param originalMap  <span class="en-US">Original data map</span>
		 *                     <span class="zh-CN">来源数据Map</span>
		 */
		@SuppressWarnings("unchecked")
		void copyData(final Object targetObject, final Map<String, Object> originalMap) {
			if (originalMap == null || originalMap.isEmpty()) {
				return;
			}
			Object fieldValue = originalMap.get(this.fieldName);
			if (fieldValue instanceof Map
					&& !ObjectUtils.nullSafeEquals(this.fieldType, fieldValue.getClass())) {
				Object targetValue = ReflectionUtils.getFieldValue(this.fieldName, targetObject);
				if (targetValue == null) {
					targetValue = ObjectUtils.newInstance(this.fieldType);
				}
				BeanUtils.copyData((Map<String, Object>) fieldValue, targetValue);
				ReflectionUtils.setField(this.fieldName, targetObject, targetValue);
			} else {
				ReflectionUtils.setField(this.fieldName, targetObject, fieldValue);
			}
		}

		/**
		 * <h3 class="en-US">Copy the property values from the JavaBean instance to JavaBean instance arrays</h3>
		 * <h3 class="zh-CN">在JavaBean实例对象复制数据到JavaBean实例对象数组</h3>
		 *
		 * @param object  <span class="en-US">JavaBean instance</span>
		 *                <span class="zh-CN">JavaBean实例</span>
		 * @param objects <span class="en-US">JavaBean instance array</span>
		 *                <span class="zh-CN">JavaBean实例数组</span>
		 */
		void marshall(final Object object, final Object... objects) {
			if (object == null || objects == null || objects.length == 0) {
				return;
			}

			Object fieldValue = ReflectionUtils.getFieldValue(this.fieldName, object);
			if (fieldValue == null) {
				return;
			}

			for (Object target : objects) {
				this.propertyMappings.stream()
						.filter(propertyMapping -> propertyMapping.match(target))
						.forEach(propertyMapping ->
								ReflectionUtils.setField(propertyMapping.getFieldName(), target,
										propertyMapping.marshal(fieldValue)));
			}
		}

		/**
		 * <h3 class="en-US">Copy the property values from JavaBean instance arrays to the target JavaBean instance</h3>
		 * <h3 class="zh-CN">从JavaBean实例对象数组复制数据到目标JavaBean实例对象</h3>
		 *
		 * @param object  <span class="en-US">JavaBean instance</span>
		 *                <span class="zh-CN">JavaBean实例</span>
		 * @param objects <span class="en-US">JavaBean instance array</span>
		 *                <span class="zh-CN">JavaBean实例数组</span>
		 */
		void unmarshall(final Object object, final Object... objects) {
			if (object == null || objects == null || objects.length == 0) {
				return;
			}
			for (PropertyMapping propertyMapping : this.propertyMappings) {
				for (Object source : objects) {
					if (propertyMapping.match(source)) {
						Object fieldValue = ReflectionUtils.getFieldValue(propertyMapping.getFieldName(), source);
						ReflectionUtils.setField(this.fieldName, object, propertyMapping.unmarshal(fieldValue));
					}
				}
			}
		}

		/**
		 * <h3 class="en-US">Register BeanProperty annotation who was annotated at field</h3>
		 * <h3 class="zh-CN">注册注解在属性上的BeanProperty注解</h3>
		 *
		 * @param beanProperty <span class="en-US">Annotation instance of BeanProperty</span>
		 *                     <span class="zh-CN">BeanProperty注解实例</span>
		 */
		private void registerProperty(final BeanProperty beanProperty) {
			Field field = ReflectionUtils.getFieldIfAvailable(beanProperty.targetBean(), beanProperty.targetField());
			if (field == null) {
				return;
			}
			PropertyMapping propertyMapping = new PropertyMapping(beanProperty);
			if (this.propertyMappings.stream().anyMatch(existMapping -> existMapping.exists(beanProperty))) {
				LOGGER.warn("JavaBean_Property_Mapping_Existed_Warn",
						beanProperty.targetBean(), beanProperty.targetField());
				this.propertyMappings.replaceAll(existMapping -> {
					if (existMapping.exists(beanProperty)) {
						return propertyMapping;
					}
					return existMapping;
				});
			} else {
				this.propertyMappings.add(propertyMapping);
			}
		}
	}

	private static final class PropertyMapping {
		private final int sortCode;
		private final String targetBeanClass;
		private final String fieldName;
		private final TransferConfig transferConfig;

		PropertyMapping(final BeanProperty beanProperty) {
			this.sortCode = beanProperty.sortCode();
			this.targetBeanClass = beanProperty.targetBean().getName();
			this.fieldName = beanProperty.targetField();
			this.transferConfig = new TransferConfig(beanProperty.transfer());
		}

		public int getSortCode() {
			return sortCode;
		}

		public String getFieldName() {
			return fieldName;
		}

		boolean exists(final BeanProperty beanProperty) {
			return ObjectUtils.nullSafeEquals(this.targetBeanClass, beanProperty.targetBean().getName())
					&& ObjectUtils.nullSafeEquals(this.fieldName, beanProperty.targetField());
		}

		boolean match(final Object object) {
			if (object == null) {
				return Boolean.FALSE;
			}
			return ObjectUtils.nullSafeEquals(this.targetBeanClass, ClassUtils.originalClassName(object.getClass()));
		}

		int compare(final PropertyMapping propertyMapping) {
			if (this.sortCode != propertyMapping.getSortCode()) {
				return Integer.compare(propertyMapping.getSortCode(), this.sortCode);
			}
			if (!ObjectUtils.nullSafeEquals(this.targetBeanClass, propertyMapping.targetBeanClass)) {
				return propertyMapping.targetBeanClass.compareTo(this.targetBeanClass);
			}
			return propertyMapping.getFieldName().compareTo(this.fieldName);
		}

		String marshal(final Object object) {
			return this.transferConfig.marshal(object);
		}

		Object unmarshal(final Object object) {
			return this.transferConfig.unmarshal(object);
		}
	}
}