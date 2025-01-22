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

import jakarta.annotation.Nonnull;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlType;
import org.nervousync.beans.core.BeanObject;
import org.nervousync.commons.Globals;
import org.nervousync.enumerations.xml.DataType;

import java.lang.reflect.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.*;
import java.util.stream.Stream;

/**
 * <h2 class="en-US">Class Operate Utilities</h2>
 * <h2 class="zh-CN">类操作工具集</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Jan 13, 2010 15:53:41 $
 */
public final class ClassUtils {
	/**
	 * <span class="en-US">Suffix for array class names: "[]"</span>
	 * <span class="zh-CN">数组类名称后缀：“[]”</span>
	 */
	private static final String ARRAY_SUFFIX = "[]";
	/**
	 * <span class="en-US">Prefix for internal array class names: "[L"</span>
	 * <span class="zh-CN">内部数组类名的前缀：“[L”</span>
	 */
	private static final String INTERNAL_ARRAY_PREFIX = "[L";
	/**
	 * <span class="en-US">The inner class separator character '$'</span>
	 * <span class="zh-CN">内部类分隔符'$'</span>
	 */
	private static final char INNER_CLASS_SEPARATOR = '$';
	/**
	 * <span class="en-US">The CGLIB class separator character "$$"</span>
	 * <span class="zh-CN">CGLIB 类分隔符 “$$”</span>
	 */
	private static final String CGLIB_CLASS_SEPARATOR = "$$";
	/**
	 * <span class="en-US">The Bytebuddy class separator character "$ByteBuddy"</span>
	 * <span class="zh-CN">Bytebuddy 类分隔符“$ByteBuddy”</span>
	 */
	private static final String BYTEBUDDY_CLASS_SEPARATOR = "$ByteBuddy";
	/**
	 * <span class="en-US">The ".class" file suffix</span>
	 * <span class="zh-CN">“.class”文件后缀</span>
	 */
	public static final String CLASS_FILE_SUFFIX = ".class";
	/**
	 * <span class="en-US">Simple data types list</span>
	 * <span class="zh-CN">简单数据类型列表</span>
	 */
	private static final List<DataType> SIMPLE_DATA_TYPES =
			Arrays.asList(DataType.NUMBER, DataType.STRING, DataType.BOOLEAN, DataType.DATE);
	/**
	 * <span class="en-US">
	 * Map with the primitive wrapper type as a key and corresponding primitive type as value,
	 * for example, Integer.class -> int.class.
	 * </span>
	 * <span class="zh-CN">以原始包装类型作为键并以相应的原始类型作为值进行映射，例如：Integer.class -> int.class。</span>
	 */
	private static final Map<Object, Object> PRIMITIVE_WRAPPER_TYPE_MAP = new HashMap<>(8);
	/**
	 * <span class="en-US">
	 * Map with primitive type name as a key and corresponding primitive type as value,
	 * for example, "int" -> "int.class".
	 * </span>
	 * <span class="zh-CN">以原始类型名称作为键，以相应的原始类型作为值的映射，例如：“int”->“int.class”。</span>
	 */
	private static final Map<Object, Object> PRIMITIVE_TYPE_NAME_MAP = new HashMap<>(16);
	/**
	 * <span class="en-US">Default classloader of utilities</span>
	 * <span class="zh-CN">工具集用的默认类加载器</span>
	 */
	private static ClassLoader DEFAULT_CLASSLOADER = null;

	static {
		PRIMITIVE_WRAPPER_TYPE_MAP.put(Boolean.class, boolean.class);
		PRIMITIVE_WRAPPER_TYPE_MAP.put(Byte.class, byte.class);
		PRIMITIVE_WRAPPER_TYPE_MAP.put(Character.class, char.class);
		PRIMITIVE_WRAPPER_TYPE_MAP.put(Double.class, double.class);
		PRIMITIVE_WRAPPER_TYPE_MAP.put(Float.class, float.class);
		PRIMITIVE_WRAPPER_TYPE_MAP.put(Integer.class, int.class);
		PRIMITIVE_WRAPPER_TYPE_MAP.put(Long.class, long.class);
		PRIMITIVE_WRAPPER_TYPE_MAP.put(Short.class, short.class);

		Set<Object> primitiveTypeNames = new HashSet<>(16);
		primitiveTypeNames.addAll(PRIMITIVE_WRAPPER_TYPE_MAP.values());
		primitiveTypeNames.addAll(Arrays.asList(
				boolean[].class, byte[].class, char[].class, double[].class,
				float[].class, int[].class, long[].class, short[].class));
		primitiveTypeNames.forEach(primitiveClass ->
				PRIMITIVE_TYPE_NAME_MAP.put(((Class<?>) primitiveClass).getName(), primitiveClass));
	}

	/**
	 * <h3 class="en-US">Private constructor for ClassUtils</h3>
	 * <h3 class="zh-CN">类操作工具集的私有构造函数</h3>
	 */
	private ClassUtils() {
	}

	/**
	 * <h3 class="en-US">Check type class is simple data class, e.g., Number (include int, Integer, long, Long...), String, boolean and Date</h3>
	 * <h3 class="zh-CN">检查类型类是简单的数据类，例如Number（包括 int、Integer、long、Long...）、String、布尔值和日期时间</h3>
	 *
	 * @param typeClass <span class="en-US">Will check for type class</span>
	 *                  <span class="zh-CN">要检查的数据类</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean simpleDataType(final Class<?> typeClass) {
		return SIMPLE_DATA_TYPES.contains(retrieveSimpleDataType(typeClass));
	}

	/**
	 * <h3 class="en-US">Retrieve simple data type enumeration value of the given data type class.</h3>
	 * <h3 class="zh-CN">检索给定数据类型类的简单数据类型枚举值。</h3>
	 *
	 * @param clazz <span class="en-US">data type class</span>
	 *              <span class="zh-CN">数据类型类</span>
	 * @return <span class="en-US">Retrieved simple data type enumeration value</span>
	 * <span class="zh-CN">检索到的简单数据类型枚举值</span>
	 */
	public static DataType retrieveSimpleDataType(final Class<?> clazz) {
		if (clazz == null) {
			return DataType.UNKNOWN;
		}

		if (clazz.equals(Character[].class) || clazz.equals(char[].class)) {
			return DataType.CDATA;
		} else if (clazz.equals(Byte[].class) || clazz.equals(byte[].class)) {
			return DataType.BINARY;
		} else if (clazz.equals(Boolean.class) || clazz.equals(boolean.class)) {
			return DataType.BOOLEAN;
		} else if (clazz.equals(Date.class)) {
			return DataType.DATE;
		} else if (clazz.equals(Integer.class) || clazz.equals(int.class)
				|| clazz.equals(Float.class) || clazz.equals(float.class)
				|| clazz.equals(Double.class) || clazz.equals(double.class)
				|| clazz.equals(Short.class) || clazz.equals(short.class)
				|| clazz.equals(Long.class) || clazz.equals(long.class)
				|| clazz.equals(byte.class) || clazz.equals(BigInteger.class)
				|| clazz.equals(BigDecimal.class) || clazz.equals(Number.class)) {
			return DataType.NUMBER;
		} else if (clazz.equals(String.class)) {
			return DataType.STRING;
		} else if (ClassUtils.isAssignable(clazz, BeanObject.class)
				&& (clazz.isAnnotationPresent(XmlType.class) || clazz.isAnnotationPresent(XmlRootElement.class))) {
			return DataType.OBJECT;
		} else if (clazz.isEnum()) {
			return DataType.ENUM;
		} else {
			return DataType.UNKNOWN;
		}
	}

	/**
	 * <h3 class="en-US">Parse simple data value to target class instance.</h3>
	 * <h3 class="zh-CN">解析简单数据类型值为目标类实例对象。</h3>
	 *
	 * @param <T>       <span class="en-US">Target type class</span>
	 *                  <span class="zh-CN">目标数据类</span>
	 * @param dataValue <span class="en-US">simple data value</span>
	 *                  <span class="zh-CN">简单数据类型值</span>
	 * @param typeClass <span class="en-US">Target type class</span>
	 *                  <span class="zh-CN">目标数据类</span>
	 * @return <span class="en-US">Target class instance</span>
	 * <span class="zh-CN">目标类实例对象</span>
	 */
	@SuppressWarnings("unchecked")
	public static <T> T parseSimpleData(final String dataValue, final Class<T> typeClass) {
		if (StringUtils.isEmpty(dataValue) || typeClass == null) {
			return null;
		}
		if (ClassUtils.isAssignable(typeClass, BeanObject.class)) {
			return StringUtils.stringToObject(dataValue, typeClass);
		}
		Object paramObj = null;
		DataType dataType = retrieveSimpleDataType(typeClass);
		switch (dataType) {
			case BOOLEAN:
				paramObj = Boolean.valueOf(dataValue);
				break;
			case DATE:
				paramObj = DateTimeUtils.parseSiteMapDate(dataValue);
				break;
			case ENUM:
				paramObj = ReflectionUtils.parseEnum(typeClass, dataValue);
				break;
			case NUMBER:
				if (typeClass.equals(Integer.class) || typeClass.equals(int.class)) {
					paramObj = Integer.valueOf(dataValue);
				} else if (typeClass.equals(Float.class) || typeClass.equals(float.class)) {
					paramObj = Float.valueOf(dataValue);
				} else if (typeClass.equals(Double.class) || typeClass.equals(double.class)) {
					paramObj = Double.valueOf(dataValue);
				} else if (typeClass.equals(Short.class) || typeClass.equals(short.class)) {
					paramObj = Short.valueOf(dataValue);
				} else if (typeClass.equals(Long.class) || typeClass.equals(long.class)) {
					paramObj = Long.valueOf(dataValue);
				} else if (typeClass.equals(BigInteger.class)) {
					paramObj = new BigInteger(dataValue);
				} else if (typeClass.equals(BigDecimal.class)) {
					paramObj = new BigDecimal(dataValue);
				}
				break;
			case CDATA:
				paramObj = StringUtils.formatForText(dataValue).toCharArray();
				break;
			case BINARY:
				paramObj = StringUtils.base64Decode(
						StringUtils.replace(dataValue, " ", Globals.DEFAULT_VALUE_STRING));
				break;
			default:
				paramObj = StringUtils.formatForText(dataValue);
		}
		return Optional.ofNullable(paramObj)
				.map(value -> {
					if (typeClass.isPrimitive()) {
						return (T) value;
					}
					return typeClass.cast(value);
				})
				.orElse(null);
	}

	/**
	 * <h3 class="en-US">Return the default ClassLoader to use</h3>
	 * <span class="en-US">
	 * Typically the thread context ClassLoader, if available;
	 * the ClassLoader that loaded the ClassUtils class will be used as fallback.
	 * Call this method if you intend to use the thread context ClassLoader
	 * in a scenario where you absolutely need a non-null ClassLoader reference:
	 * for example, for class path resource loading (but not necessarily for
	 * <code>Class.forName</code>, which accepts a <code>null</code> ClassLoader
	 * reference as well).
	 * </span>
	 * <h3 class="zh-CN">返回要使用的默认类加载器</h3>
	 * <span class="zh-CN">
	 * 通常是线程上下文类加载器（如果可用）；加载 ClassUtils 类的类加载器将用作后备。
	 * 如果您打算在绝对需要非空类加载器引用的情况下使用线程上下文类加载器，请调用此方法：
	 * 例如，用于类路径资源加载（但不一定用于 <code>Class.forName</code>，它也接受 <code>null</code> ClassLoader 引用）。
	 * </span>
	 *
	 * @return <span class="en-US">the default ClassLoader (never <code>null</code>)</span>
	 * <span class="zh-CN">默认的类加载器（永远不为<code>null</code>）</span>
	 * @see java.lang.Thread#getContextClassLoader() java.lang.Thread#getContextClassLoader()
	 */
	public static ClassLoader getDefaultClassLoader() {
		if (DEFAULT_CLASSLOADER != null) {
			return DEFAULT_CLASSLOADER;
		}
		try {
			return Thread.currentThread().getContextClassLoader();
		} catch (Throwable ex) {
			// Cannot access thread context ClassLoader - falling back to system class loader...
			return ClassUtils.class.getClassLoader();
		}
	}

	/**
	 * <h3 class="en-US">Override the thread context ClassLoader</h3>
	 * <span class="en-US">
	 * Override the thread context ClassLoader with the environment's bean ClassLoader if necessary,
	 * i.e., if the bean ClassLoader is not equivalent to the thread context ClassLoader already.
	 * </span>
	 * <h3 class="zh-CN">重写线程上下文类加载器</h3>
	 * <span class="zh-CN">如有必要，建议使用环境的类加载器覆写线程上下文类加载器。</span>
	 *
	 * @param classLoaderToUse <span class="en-US">the actual ClassLoader to use for the thread context</span>
	 *                         <span class="zh-CN">用于线程上下文的实际类加载器</span>
	 * @return <span class="en-US">the original thread context ClassLoader, or <code>null</code> if not overridden</span>
	 * <span class="zh-CN">原始线程上下文类加载器，如果未覆盖则为 <code>null</code></span>
	 */
	public static ClassLoader overrideThreadContextClassLoader(final ClassLoader classLoaderToUse) {
		Thread thread = Thread.currentThread();
		ClassLoader contextClassLoader = thread.getContextClassLoader();
		if (classLoaderToUse != null && !classLoaderToUse.equals(contextClassLoader)) {
			thread.setContextClassLoader(classLoaderToUse);
			DEFAULT_CLASSLOADER = classLoaderToUse;
			return contextClassLoader;
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Determine whether the <code>Class</code> identified by the supplied name is present and can be loaded.</h3>
	 * <span class="en-US">
	 * Will return <code>Boolean.FALSE</code> if either the class or
	 * one of its dependencies is not present or cannot be loaded.
	 * </span>
	 * <h3 class="zh-CN">确定由提供的名称标识的 <code>Class</code> 是否存在并且可以加载。</h3>
	 * <span class="zh-CN">如果类或其依赖项之一不存在或无法加载，将返回 Boolean.FALSE。</span>
	 *
	 * @param className <span class="en-US">the name of the class to check</span>
	 *                  <span class="zh-CN">要检查的类的名称</span>
	 * @return <span class="en-US">whether the specified class is present</span>
	 * <span class="zh-CN">指定的类是否存在</span>
	 */
	public static boolean isPresent(final String className) {
		return isPresent(className, getDefaultClassLoader());
	}

	/**
	 * <h3 class="en-US">Determine whether the <code>Class</code> identified by the supplied name is present and can be loaded.</h3>
	 * <span class="en-US">
	 * Will return <code>Boolean.FALSE</code> if either the class or
	 * one of its dependencies is not present or cannot be loaded.
	 * </span>
	 * <h3 class="zh-CN">确定由提供的名称标识的 <code>Class</code> 是否存在并且可以加载。</h3>
	 * <span class="zh-CN">如果类或其依赖项之一不存在或无法加载，将返回 Boolean.FALSE。</span>
	 *
	 * @param className   <span class="en-US">the name of the class to check</span>
	 *                    <span class="zh-CN">要检查的类的名称</span>
	 * @param classLoader <span class="en-US">the ClassLoader to use (maybe <code>null</code>, which indicates the default ClassLoader)</span>
	 *                    <span class="zh-CN">要使用的类加载器（可能是 <code>null</code>，这表示默认的类加载器）</span>
	 * @return <span class="en-US">whether the specified class is present</span>
	 * <span class="zh-CN">指定的类是否存在</span>
	 */
	public static boolean isPresent(final String className, final ClassLoader classLoader) {
		try {
			forName(className, classLoader);
			return Boolean.TRUE;
		} catch (Throwable ex) {
			// Class or one of its dependencies is not present...
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Check whether the given exception is compatible with the exceptions declared in a throw clause.</h3>
	 * <h3 class="zh-CN">检查给定的异常是否与 throw 子句中声明的异常兼容。</h3>
	 *
	 * @param ex                 <span class="en-US">the exception to checked</span>
	 *                           <span class="zh-CN">要检查的异常</span>
	 * @param declaredExceptions <span class="en-US">the exceptions declared in the throw clause</span>
	 *                           <span class="zh-CN">throw 子句中声明的异常</span>
	 * @return <span class="en-US">whether the given exception is compatible</span>
	 * <span class="zh-CN">给定的异常是否兼容</span>
	 */
	public static boolean isCompatibleWithThrowClause(final Throwable ex, final Class<?>[] declaredExceptions) {
		if (ex instanceof RuntimeException || ex instanceof Error) {
			return Boolean.TRUE;
		}
		if (declaredExceptions != null) {
			return Arrays.stream(declaredExceptions)
					.anyMatch(declaredException -> ClassUtils.isAssignableValue(declaredException, ex));
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Parse the original class name of given class instance</h3>
	 * <p class="en-US">Unwrap the class name if class was enhancer by cglib/bytebuddy or class name if class not enhanced</p>
	 * <h3 class="zh-CN">解析给定类对象的原始类名</h3>
	 * <p class="zh-CN">如果给定的类是经过cglib/bytebuddy增强过，则解析原始类名，如果给定的类没有增强，则返回类名</p>
	 *
	 * @param clazz <span class="en-US">Given class instance</span>
	 *              <span class="zh-CN">给定的类对象</span>
	 * @return <span class="en-US">Parsed class name string</span>
	 * <span class="zh-CN">解析的类名字符串</span>
	 */
	public static String originalClassName(final Class<?> clazz) {
		String className = clazz.getName();
		if (className.contains(CGLIB_CLASS_SEPARATOR)) {
			//  Process for cglib
			className = className.substring(0, className.indexOf(CGLIB_CLASS_SEPARATOR));
		} else if (className.contains(BYTEBUDDY_CLASS_SEPARATOR)) {
			//  Process for ByteBuddy
			className = className.substring(0, className.indexOf(BYTEBUDDY_CLASS_SEPARATOR));
		}
		return className;
	}

	/**
	 * <h3 class="en-US">Replacement for <code>Class.forName()</code></h3>
	 * <span class="en-US">
	 * Replacement for <code>Class.forName()</code> that also returns Class instances
	 * for primitives (like "int") and array class names (like "String[]").
	 * Always use the default class loader: that is, preferably the thread context
	 * ClassLoader, or the ClassLoader that loaded the ClassUtils class as fallback.
	 * </span>
	 * <h3 class="zh-CN">替换 <code>Class.forName()</code></h3>
	 * <span class="zh-CN">
	 * 替换 <code>Class.forName()</code>，它还返回基础类型（如“int”）和数组类名称（如“String[]”）的类实例。
	 * 始终使用默认的类加载器：最好是线程上下文类加载器，或者加载 ClassUtils 类作为后备的类加载器。
	 * </span>
	 *
	 * @param className <span class="en-US">the name of the class</span>
	 *                  <span class="zh-CN">类的名称</span>
	 * @return <span class="en-US">Class instance for the supplied name</span>
	 * <span class="zh-CN">提供的名称的类实例</span>
	 * @throws IllegalArgumentException <span class="en-US">if the class name was not resolvable (that is, the class could not be found or the class file could not be loaded)</span>
	 *                                  <span class="zh-CN">如果类名不可解析（即找不到类或无法加载类文件）</span>
	 * @see Class#forName(String, boolean, ClassLoader) Class#forName(String, boolean, ClassLoader)
	 * @see ClassUtils#getDefaultClassLoader()
	 */
	public static Class<?> forName(final String className) throws IllegalArgumentException {
		return forName(className, getDefaultClassLoader());
	}

	/**
	 * <h3 class="en-US">Replacement for <code>Class.forName()</code></h3>
	 * <span class="en-US">
	 * Replacement for <code>Class.forName()</code> that also returns Class instances
	 * for primitives (like "int") and array class names (like "String[]").
	 * </span>
	 * <h3 class="zh-CN">替换 <code>Class.forName()</code></h3>
	 * <span class="zh-CN">
	 * 替换 <code>Class.forName()</code>，它还返回基础类型（如“int”）和数组类名称（如“String[]”）的类实例。
	 * </span>
	 *
	 * @param className   <span class="en-US">the name of the class</span>
	 *                    <span class="zh-CN">类的名称</span>
	 * @param classLoader <span class="en-US">the ClassLoader to use (maybe <code>null</code>, which indicates the default ClassLoader)</span>
	 *                    <span class="zh-CN">要使用的类加载器（可能是 <code>null</code>，这表示默认的类加载器）</span>
	 * @return <span class="en-US">Class instance for the supplied name</span>
	 * <span class="zh-CN">提供的名称的类实例</span>
	 * @throws IllegalArgumentException <span class="en-US">if the class name was not resolvable (that is, the class could not be found or the class file could not be loaded)</span>
	 *                                  <span class="zh-CN">如果类名不可解析（即找不到类或无法加载类文件）</span>
	 * @see Class#forName(String, boolean, ClassLoader) Class#forName(String, boolean, ClassLoader)
	 */
	public static Class<?> forName(final String className, final ClassLoader classLoader)
			throws IllegalArgumentException {
		if (StringUtils.isEmpty(className)) {
			throw new IllegalArgumentException("Class name must not be empty");
		}

		if (StringUtils.notBlank(className) && className.length() <= 8
				&& PRIMITIVE_TYPE_NAME_MAP.containsKey(className)) {
			return (Class<?>) PRIMITIVE_TYPE_NAME_MAP.get(className);
		}

		// "java.lang.String[]" style arrays
		if (className.endsWith(ARRAY_SUFFIX)) {
			String elementClassName = className.substring(0, className.length() - ARRAY_SUFFIX.length());
			Class<?> elementClass = forName(elementClassName, classLoader);
			return Array.newInstance(elementClass, 0).getClass();
		}

		int internalArrayMarker = className.indexOf(INTERNAL_ARRAY_PREFIX);
		if (internalArrayMarker != -1 && className.endsWith(";")) {
			String elementClassName = null;
			if (internalArrayMarker == 0) {
				elementClassName = className.substring(INTERNAL_ARRAY_PREFIX.length(), className.length() - 1);
			} else if (className.startsWith("[")) {
				elementClassName = className.substring(1);
			}
			Class<?> elementClass = forName(elementClassName, classLoader);
			return Array.newInstance(elementClass, 0).getClass();
		}

		ClassLoader classLoaderToUse = classLoader;
		if (classLoaderToUse == null) {
			classLoaderToUse = getDefaultClassLoader();
		}
		try {
			return classLoaderToUse.loadClass(className);
		} catch (ClassNotFoundException ex) {
			throw new IllegalArgumentException("Cannot find class [" + className + "]", ex);
		}
	}

	/**
	 * <h3 class="en-US">Check whether the given class is cache-safe in the given context</h3>
	 * <span class="en-US">whether it is loaded by the given ClassLoader or a parent of it.</span>
	 * <h3 class="zh-CN">检查给定类在给定上下文中是否是缓存安全的</h3>
	 * <span class="zh-CN">它是由给定的类加载器还是其父类加载。</span>
	 *
	 * @param clazz       <span class="en-US">the class to analyze</span>
	 *                    <span class="zh-CN">要分析的类</span>
	 * @param classLoader <span class="en-US">the ClassLoader to potentially cache metadata in</span>
	 *                    <span class="zh-CN">可能会缓存元数据的类加载器</span>
	 * @return <span class="en-US">cache safe result</span>
	 * <span class="zh-CN">缓存安全结果</span>
	 */
	public static boolean cacheSafe(final Class<?> clazz, final ClassLoader classLoader) {
		if (clazz == null) {
			throw new IllegalArgumentException("Class must not be null");
		}
		ClassLoader target = clazz.getClassLoader();
		if (target == null) {
			return Boolean.FALSE;
		}
		ClassLoader cur = classLoader;
		if (cur == target) {
			return Boolean.TRUE;
		}
		while (cur != null) {
			cur = cur.getParent();
			if (cur == target) {
				return Boolean.TRUE;
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Determine the resource name of the class file, relative to the containing package: e.g. "String.class"</h3>
	 * <h3 class="zh-CN">确定类文件的资源路径：例如“String.class”</h3>
	 *
	 * @param clazz <span class="en-US">the class instance</span>
	 *              <span class="zh-CN">类实例对象</span>
	 * @return <span class="en-US">the resource path of the ".class" file</span>
	 * <span class="zh-CN">".class"文件的资源路径</span>
	 */
	public static String classFileName(final Class<?> clazz) {
		if (clazz == null) {
			throw new IllegalArgumentException("Class must not be null");
		}
		String className = clazz.getName();
		int lastDotIndex = className.lastIndexOf(Globals.DEFAULT_PACKAGE_SEPARATOR);
		return className.substring(lastDotIndex + 1) + CLASS_FILE_SUFFIX;
	}

	/**
	 * <h3 class="en-US">Determine the package name of the given class.</h3>
	 * <span class="en-US">e.g. "java.lang" for the <code>java.lang.String</code> class.</span>
	 * <h3 class="zh-CN">确定给定类的包名称。</h3>
	 * <span class="zh-CN">例如：<code>java.lang.String</code> -> “java.lang”</span>
	 *
	 * @param clazz <span class="en-US">the class instance</span>
	 *              <span class="zh-CN">类实例对象</span>
	 * @return <span class="en-US">the package name, or the empty String if the class is defined in the default package</span>
	 * <span class="zh-CN">包名称，如果类是在默认包中定义的，则为空字符串</span>
	 */
	public static String packageName(final Class<?> clazz) {
		if (clazz == null) {
			throw new IllegalArgumentException("Class must not be null");
		}
		String className = clazz.getName();
		int lastDotIndex = className.lastIndexOf(Globals.DEFAULT_PACKAGE_SEPARATOR);
		return (lastDotIndex != -1 ? className.substring(0, lastDotIndex) : Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * <h3 class="en-US">Return the qualified name of the given class.</h3>
	 * <span class="en-US">usually simply the class name, but component type class name + "[]" for arrays.</span>
	 * <h3 class="zh-CN">返回给定类的限定名称。</h3>
	 * <span class="zh-CN">通常只是类名，但对于数组来说组件类型类名+“[]”。</span>
	 *
	 * @param clazz <span class="en-US">the class instance</span>
	 *              <span class="zh-CN">类实例对象</span>
	 * @return <span class="en-US">the qualified name of the class</span>
	 * <span class="zh-CN">类的限定名称</span>
	 */
	public static String qualifiedName(final Class<?> clazz) {
		if (clazz == null) {
			throw new IllegalArgumentException("Class must not be null");
		}
		if (clazz.isArray()) {
			return getQualifiedNameForArray(clazz);
		} else {
			return clazz.getName();
		}
	}

	/**
	 * <h3 class="en-US">Return a descriptive name for the given object's type.</h3>
	 * <span class="en-US">
	 * usually simply the class name, but component type class name + "[]" for arrays,
	 * and an appended list of implemented interfaces for JDK proxies.
	 * </span>
	 * <h3 class="zh-CN">返回给定对象类型的描述性名称。</h3>
	 * <span class="zh-CN">通常只是类名，但组件类型类名+数组的“[]”，以及JDK代理的已实现接口的附加列表。</span>
	 *
	 * @param value <span class="en-US">the value to introspect</span>
	 *              <span class="zh-CN">给定实例对象</span>
	 * @return <span class="en-US">the descriptive name of the class</span>
	 * <span class="zh-CN">实现的接口名称</span>
	 */
	public static String descriptiveType(final Object value) {
		if (value == null) {
			return null;
		}
		Class<?> clazz = value.getClass();
		if (Proxy.isProxyClass(clazz)) {
			final StringBuilder stringBuilder = new StringBuilder();
			Arrays.asList(clazz.getInterfaces())
					.forEach(interfaceClass -> stringBuilder.append(",").append(interfaceClass.getName()));
			return clazz.getName() + " implementing " + stringBuilder.substring(1);
		} else if (clazz.isArray()) {
			return getQualifiedNameForArray(clazz);
		} else {
			return clazz.getName();
		}
	}

	/**
	 * <h3 class="en-US">Retrieve the primitive class of the given class.</h3>
	 * <h3 class="zh-CN">检索给定类的原始类。</h3>
	 *
	 * @param clazz <span class="en-US">the class instance</span>
	 *              <span class="zh-CN">类实例对象</span>
	 * @return <span class="en-US">the primitive class or <code>null</code> if not found</span>
	 * <span class="zh-CN">原始类，如果未找到则返回<code>null</code></span>
	 */
	public static Class<?> primitiveWrapper(final Class<?> clazz) {
		if (clazz.isPrimitive()) {
			for (Map.Entry<Object, Object> entry : PRIMITIVE_WRAPPER_TYPE_MAP.entrySet()) {
				if (entry.getValue().equals(clazz)) {
					return (Class<?>) entry.getKey();
				}
			}
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Check the given check class and match class is mapping for primitive class -> wrapper class</h3>
	 * <h3 class="zh-CN">检查给定的检查类和匹配类是否满足映射为原始类 -> 包装类</h3>
	 *
	 * @param checkClass <span class="en-US">the check class</span>
	 *                   <span class="zh-CN">检查类</span>
	 * @param matchClass <span class="en-US">the match class</span>
	 *                   <span class="zh-CN">匹配类</span>
	 * @return <span class="en-US">Match result</span>
	 * <span class="zh-CN">匹配结果</span>
	 */
	public static boolean matchPrimitiveWrapper(final Class<?> checkClass, final Class<?> matchClass) {
		if (isPrimitiveWrapper(checkClass)) {
			return PRIMITIVE_WRAPPER_TYPE_MAP.get(checkClass).equals(matchClass);
		} else if (isPrimitiveWrapper(matchClass)) {
			return PRIMITIVE_WRAPPER_TYPE_MAP.get(matchClass).equals(checkClass);
		} else {
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Check if the given class represents a primitive wrapper.</h3>
	 * <span class="en-US">i.e., Boolean, Byte, Character, Short, Integer, Long, Float, or Double.</span>
	 * <h3 class="zh-CN">检查给定的类是否表示基础类型包装类。</h3>
	 * <span class="zh-CN">即 Boolean, Byte, Character, Short, Integer, Long, Float, or Double.</span>
	 *
	 * @param clazz <span class="en-US">the class to check</span>
	 *              <span class="zh-CN">要检查的类</span>
	 * @return <span class="en-US">whether the given class is a primitive wrapper class</span>
	 * <span class="zh-CN">给定的类是否为基础类型包装类</span>
	 */
	public static boolean isPrimitiveWrapper(final Class<?> clazz) {
		if (clazz == null) {
			throw new IllegalArgumentException("Class must not be null");
		}
		return PRIMITIVE_WRAPPER_TYPE_MAP.containsKey(clazz);
	}

	/**
	 * <h3 class="en-US">Check if the given class is a primitive or primitive wrapper class.</h3>
	 * <span class="en-US">
	 * a primitive (i.e., boolean, byte, char, short, int, long, float, or double)
	 * or a primitive wrapper (i.e., Boolean, Byte, Character, Short, Integer, Long, Float, or Double)
	 * </span>
	 * <h3 class="zh-CN">检查给定的类是否是基础类型或基础类型包装类。</h3>
	 * <span class="zh-CN">
	 * 即基础类型(boolean, byte, char, short, int, long, float, double)
	 * 或者包装类（Boolean, Byte, Character, Short, Integer, Long, Float, Double）。
	 * </span>
	 *
	 * @param clazz <span class="en-US">the class to check</span>
	 *              <span class="zh-CN">要检查的类</span>
	 * @return <span class="en-US">whether the given class is a primitive or primitive wrapper class</span>
	 * <span class="zh-CN">给定的类是否为基础类型或基础类型包装类</span>
	 */
	public static boolean isPrimitiveOrWrapper(final Class<?> clazz) {
		if (clazz == null) {
			throw new IllegalArgumentException("Class must not be null");
		}
		return (clazz.isPrimitive() || isPrimitiveWrapper(clazz));
	}

	/**
	 * <h3 class="en-US">Check if the given class represents an array of primitives.</h3>
	 * <span class="en-US">i.e., Boolean, Byte, Character, Short, Integer, Long, Float, or Double.</span>
	 * <h3 class="zh-CN">检查给定的类是否表示基础类型数组。</h3>
	 * <span class="zh-CN">即 Boolean, Byte, Character, Short, Integer, Long, Float, Double.</span>
	 *
	 * @param clazz <span class="en-US">the class to check</span>
	 *              <span class="zh-CN">要检查的类</span>
	 * @return <span class="en-US">whether the given class is a primitive array class</span>
	 * <span class="zh-CN">给定的类是否为基础类型数组</span>
	 */
	public static boolean isPrimitiveArray(final Class<?> clazz) {
		if (clazz == null) {
			throw new IllegalArgumentException("Class must not be null");
		}
		return (clazz.isArray() && clazz.getComponentType().isPrimitive());
	}

	/**
	 * <h3 class="en-US">Check if the given class represents an array of primitive wrappers.</h3>
	 * <span class="en-US">i.e., Boolean, Byte, Character, Short, Integer, Long, Float, or Double.</span>
	 * <h3 class="zh-CN">检查给定的类是否表示基础类型包装类数组。</h3>
	 * <span class="zh-CN">即 Boolean, Byte, Character, Short, Integer, Long, Float, Double.</span>
	 *
	 * @param clazz <span class="en-US">the class to check</span>
	 *              <span class="zh-CN">要检查的类</span>
	 * @return <span class="en-US">whether the given class is a primitive wrapper array class</span>
	 * <span class="zh-CN">给定的类是否为基础类型包装类数组</span>
	 */
	public static boolean isPrimitiveWrapperArray(final Class<?> clazz) {
		if (clazz == null) {
			throw new IllegalArgumentException("Class must not be null");
		}
		return (clazz.isArray() && isPrimitiveWrapper(clazz.getComponentType()));
	}

	/**
	 * <h3 class="en-US">Check if the right-hand side type may be assigned to the left-hand side type.</h3>
	 * <h3 class="zh-CN">检查给定的检查类是目标类的子类或实现类</h3>
	 *
	 * @param targetType <span class="en-US">the target type</span>
	 *                   <span class="zh-CN">目标类</span>
	 * @param checkType  <span class="en-US">the value type that should be assigned to the target type</span>
	 *                   <span class="zh-CN">目标类的子类或实现类</span>
	 * @return <span class="en-US"><code>true</code> if the target type is assignable from the value type, <code>false</code> for otherwise.</span>
	 * <span class="zh-CN">检查类是目标类的子类或实现类，则返回<code>true</code>；否则返回<code>false</code>。</span>
	 */
	public static boolean isAssignable(final Class<?> targetType, final Class<?> checkType) {
		if (targetType == null) {
			throw new IllegalArgumentException("Target type must not be null");
		}
		if (checkType == null) {
			throw new IllegalArgumentException("Check type must not be null");
		}
		return (targetType.isAssignableFrom(checkType) || targetType.equals(PRIMITIVE_WRAPPER_TYPE_MAP.get(checkType)));
	}

	/**
	 * <h3 class="en-US">Determine if the given type is assignable from the given value.</h3>
	 * <h3 class="zh-CN">确定给定的值是目标类的子类或实现类</h3>
	 *
	 * @param type  <span class="en-US">the target type</span>
	 *              <span class="zh-CN">目标类</span>
	 * @param value <span class="en-US">the given value</span>
	 *              <span class="zh-CN">给定值</span>
	 * @return <span class="en-US"><code>true</code> if the given value is assignable from the given type, <code>false</code> for otherwise.</span>
	 * <span class="zh-CN">给定的值是目标类的子类或实现类，则返回<code>true</code>；否则返回<code>false</code>。</span>
	 */
	public static boolean isAssignableValue(final Class<?> type, final Object value) {
		if (type == null) {
			throw new IllegalArgumentException("Type must not be null");
		}
		return (value != null ? isAssignable(type, value.getClass()) : !type.isPrimitive());
	}

	/**
	 * <h3 class="en-US">Convert a "/"-based resource path to a "."-based fully qualified class name.</h3>
	 * <h3 class="zh-CN">将基于“/”的资源路径转换为基于“.”的完全限定类名。</h3>
	 *
	 * @param resourcePath <span class="en-US">the resource path pointing to a class</span>
	 *                     <span class="zh-CN">指向类的资源路径</span>
	 * @return <span class="en-US">the corresponding fully qualified class name.</span>
	 * <span class="zh-CN">相应的完全限定类名</span>
	 */
	public static String resourcePathToClassName(final String resourcePath) {
		String separator = resourcePath.contains(Globals.DEFAULT_PAGE_SEPARATOR)
				? Globals.DEFAULT_PAGE_SEPARATOR
				: Character.toString(Globals.DEFAULT_RESOURCE_SEPARATOR);
		StringBuilder className = new StringBuilder();
		int position = resourcePath.startsWith(separator) ? 1 : Globals.INITIALIZE_INT_VALUE;
		int index = resourcePath.indexOf(separator, position);
		while (index != Globals.DEFAULT_VALUE_INT) {
			className.append(Globals.DEFAULT_PACKAGE_SEPARATOR).append(resourcePath, position, index);
			position = index + 1;
			index = resourcePath.indexOf(separator, position);
		}
		className.append(Globals.DEFAULT_PACKAGE_SEPARATOR).append(resourcePath, position,
				resourcePath.length() - ClassUtils.CLASS_FILE_SUFFIX.length());
		return className.substring(1);
	}

	/**
	 * <h3 class="en-US">Convert a "."-based fully qualified class name to a "/"-based resource path.</h3>
	 * <h3 class="zh-CN">将基于“.”的完全限定类名转换为基于“/”的资源路径。</h3>
	 *
	 * @param className <span class="en-US">the fully qualified class name</span>
	 *                  <span class="zh-CN">完全限定的类名</span>
	 * @return <span class="en-US">the corresponding resource path, pointing to the class.</span>
	 * <span class="zh-CN">对应指向类的资源路径</span>
	 */
	public static String classNameToResourcePath(String className) {
		return className.replace(Globals.DEFAULT_PACKAGE_SEPARATOR, Globals.DEFAULT_RESOURCE_SEPARATOR) + CLASS_FILE_SUFFIX;
	}

	/**
	 * <h3 class="en-US">Return a path suitable for use with <code>ClassLoader.getResource</code>.</h3>
	 * <span class="en-US">
	 * Also suitable for use with <code>Class.getResource</code> by prepending a
	 * slash ('/') to the return value. Built by taking the package of the specified
	 * class file, converting all dots ('.') to slashes ('/'), adding a trailing slash
	 * if necessary, and concatenating the specified resource name to this.
	 * As such, this function may be used to build a path suitable for
	 * loading a resource file that is in the same package as a class file.
	 * </span>
	 * <h3 class="zh-CN">返回适用于 ClassLoader.getResource 的路径。</h3>
	 * <span class="zh-CN">
	 * 也适合与 <code>Class.getResource</code> 一起使用，方法是在返回值前添加斜杠 ('/')。通过获取指定类文件的包，
	 * 将所有点（“.”）转换为斜杠（“/”），根据需要添加尾部斜杠，并将指定的资源名称连接到此来构建。
	 * 因此，该函数可用于构建适合加载与类文件位于同一包中的资源文件的路径。
	 * </span>
	 *
	 * @param clazz        <span class="en-US">the Class whose package will be used as the base</span>
	 *                     <span class="zh-CN">其包将用作基础的类</span>
	 * @param resourceName <span class="en-US">the resource name to append. A leading slash is optional.</span>
	 *                     <span class="zh-CN">要附加的资源名称。前导斜杠是可选的。</span>
	 * @return <span class="en-US">the built-up resource path</span>
	 * <span class="zh-CN">构建的资源路径</span>
	 * @see java.lang.ClassLoader#getResource(String)
	 * @see java.lang.Class#getResource(String)
	 */
	public static String addResourcePathToPackagePath(final Class<?> clazz, final String resourceName) {
		if (resourceName == null) {
			throw new IllegalArgumentException("Resource name must not be null");
		}
		StringBuilder stringBuilder = new StringBuilder(classPackageAsResourcePath(clazz));
		if (!resourceName.startsWith(Character.toString(Globals.DEFAULT_RESOURCE_SEPARATOR))) {
			stringBuilder.append(Globals.DEFAULT_RESOURCE_SEPARATOR);
		}
		stringBuilder.append(resourceName);
		return stringBuilder.toString();
	}

	/**
	 * <h3 class="en-US">Given an input class object, return a string which consists of the class's package name as a pathname.</h3>
	 * <span class="en-US">
	 * For example, all dots ('.') are replaced by slashes ('/'). Neither a leading nor trailing slash is added.
	 * The result could be concatenated with a slash and the name of a resource, and fed directly
	 * to <code>ClassLoader.getResource()</code>. For it to be fed to <code>Class.getResource</code> instead,
	 * a leading slash would also have to be prepended to the returned value.
	 * </span>
	 * <h3 class="zh-CN">给定一个输入类对象，返回一个由类的包名作为路径名组成的字符串。</h3>
	 * <span class="zh-CN">
	 * 即，所有点（'.'）都被斜杠（'/'）替换。不添加前导斜杠或尾随斜杠。结果可以与斜杠和资源名称连接起来，
	 * 并直接提供给 <code>ClassLoader.getResource()</code>。为了将其提供给 <code>Class.getResource</code>，
	 * 还必须在返回值前面添加一个前导斜杠。
	 * </span>
	 *
	 * @param clazz <span class="en-US">the input class. A <code>null</code> value or the default (empty) package will result in an empty string ("") being returned.</span>
	 *              <span class="zh-CN">输入类。 <code>null</code> 值或默认（空）包将导致返回空字符串 ("")。</span>
	 * @return <span class="en-US">a path which represents the package name</span>
	 * <span class="zh-CN">代表包名称的路径</span>
	 * @see java.lang.ClassLoader#getResource(String)
	 * @see java.lang.Class#getResource(String)
	 */
	public static String classPackageAsResourcePath(final Class<?> clazz) {
		if (clazz == null) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		String className = clazz.getName();
		int packageEndIndex = className.lastIndexOf(Globals.DEFAULT_PACKAGE_SEPARATOR);
		if (packageEndIndex == -1) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		String packageName = className.substring(0, packageEndIndex);
		return packageName.replace(Globals.DEFAULT_PACKAGE_SEPARATOR, Globals.DEFAULT_RESOURCE_SEPARATOR);
	}

	/**
	 * <h3 class="en-US">Check given field name was exists field in target class</h3>
	 * <h3 class="zh-CN">检查给定的字段名称是否存在于目标类中</h3>
	 *
	 * @param clazz <span class="en-US">Target class instance</span>
	 *              <span class="zh-CN">目标类实例</span>
	 * @param name  <span class="en-US">the name of the field</span>
	 *              <span class="zh-CN">字段名称</span>
	 * @return <span class="en-US">the field object exists results</span>
	 * <span class="zh-CN">字段对象存在结果</span>
	 */
	public static boolean existsField(final Class<?> clazz, final String name) {
		return ReflectionUtils.findField(clazz, name) != null;
	}

	/**
	 * <h3 class="en-US">
	 * Return all interfaces that the given instance implements as arrays,
	 * including ones implemented by superclasses.
	 * </h3>
	 * <h3 class="zh-CN">返回给定实例作为数组实现的所有接口，包括由超类实现的接口。</h3>
	 *
	 * @param instance <span class="en-US">the instance to analyze for interfaces</span>
	 *                 <span class="zh-CN">用于分析接口的实例</span>
	 * @return <span class="en-US">all interfaces that the given instance implements as arrays</span>
	 * <span class="zh-CN">给定实例作为数组实现的所有接口</span>
	 */
	public static Class<?>[] getAllInterfaces(final Object instance) {
		if (instance == null) {
			throw new IllegalArgumentException("Instance must not be null");
		}
		return getAllInterfacesForClass(instance.getClass());
	}

	/**
	 * <h3 class="en-US">Return all interfaces that the given class implements as arrays, including ones implemented by superclasses.</h3>
	 * <span class="en-US">If the class itself is an interface, it gets returned as sole interface.</span>
	 * <h3 class="zh-CN">返回给定类作为数组实现的所有接口，包括由超类实现的接口。</h3>
	 * <span class="zh-CN">如果类本身是一个接口，它将作为唯一接口返回。</span>
	 *
	 * @param clazz <span class="en-US">the class to analyze for interfaces</span>
	 *              <span class="zh-CN">用于分析接口的类</span>
	 * @return <span class="en-US">all interfaces that the given instance implements as arrays</span>
	 * <span class="zh-CN">给定实例作为数组实现的所有接口</span>
	 */
	public static Class<?>[] getAllInterfacesForClass(final Class<?> clazz) {
		return getAllInterfacesForClass(clazz, null);
	}

	/**
	 * <h3 class="en-US">Return all interfaces that the given class implements as arrays, including ones implemented by superclasses.</h3>
	 * <span class="en-US">If the class itself is an interface, it gets returned as sole interface.</span>
	 * <h3 class="zh-CN">返回给定类作为数组实现的所有接口，包括由超类实现的接口。</h3>
	 * <span class="zh-CN">如果类本身是一个接口，它将作为唯一接口返回。</span>
	 *
	 * @param clazz       <span class="en-US">the class to analyze for interfaces</span>
	 *                    <span class="zh-CN">用于分析接口的类</span>
	 * @param classLoader <span class="en-US">the ClassLoader that the interfaces need to be visible in (maybe <code>null</code> when accepting all declared interfaces)</span>
	 *                    <span class="zh-CN">接口需要在其中可见的类加载器（如果为<code>null</code>，则接受所有声明的接口）</span>
	 * @return <span class="en-US">all interfaces that the given instance implements as arrays</span>
	 * <span class="zh-CN">给定实例作为数组实现的所有接口</span>
	 */
	public static Class<?>[] getAllInterfacesForClass(final Class<?> clazz, final ClassLoader classLoader) {
		if (clazz == null || clazz.isInterface()) {
			return new Class[]{clazz};
		}
		List<Class<?>> interfaces = new ArrayList<>();
		if (clazz.getSuperclass() != null) {
			List.of(getAllInterfacesForClass(clazz.getSuperclass(), classLoader))
					.forEach(interfaceClass -> {
						if (!CollectionUtils.contains(interfaces, interfaceClass)) {
							interfaces.add(interfaceClass);
						}
					});
		}
		Stream.of(clazz.getInterfaces())
				.filter(interfaceClass ->
						!CollectionUtils.contains(interfaces, interfaceClass)
								&& (classLoader == null || isVisible(interfaceClass, classLoader)))
				.forEach(interfaces::add);
		return interfaces.toArray(new Class[0]);
	}

	/**
	 * <h3 class="en-US">Check whether the given class is visible in the given ClassLoader.</h3>
	 * <h3 class="zh-CN">检查给定的类在给定的类加载器中是否可见。</h3>
	 *
	 * @param clazz       <span class="en-US">the class to check (typically an interface)</span>
	 *                    <span class="zh-CN">要检查的类（通常是接口）</span>
	 * @param classLoader <span class="en-US">the ClassLoader to check against (maybe <code>null</code> in which case this method will always return <code>Boolean.TRUE</code>)</span>
	 *                    <span class="zh-CN">要检查的类加载器（也许 <code>null</code> 在这种情况下，此方法将始终返回 <code>Boolean.TRUE</code>）</span>
	 * @return <span class="en-US">class is visible</span>
	 * <span class="zh-CN">类可见</span>
	 */
	public static boolean isVisible(final Class<?> clazz, final ClassLoader classLoader) {
		if (classLoader == null) {
			return Boolean.TRUE;
		}
		try {
			Class<?> actualClass = classLoader.loadClass(clazz.getName());
			return (clazz == actualClass);
			// Else: different interface class found...
		} catch (ClassNotFoundException ex) {
			// No interface class found...
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Parse component type from given class.</h3>
	 * <h3 class="zh-CN">从给定类中解析组件类型。</h3>
	 *
	 * @param clazz <span class="en-US">Class instance</span>
	 *              <span class="zh-CN">类实例</span>
	 * @return <span class="en-US">Parsed component type or <code>null</code> if not a list or array</span>
	 * <span class="zh-CN">解析的组件类型，如果不是列表或数组则为 <code>null</code></span>
	 */
	public static Class<?> componentType(final Class<?> clazz) {
		if (clazz.isArray()) {
			return clazz.getComponentType();
		} else if (ClassUtils.isAssignable(Collection.class, clazz)) {
			return (Class<?>) ((ParameterizedType) clazz.getGenericInterfaces()[0]).getActualTypeArguments()[0];
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Parse an array of generic types from the given class.</h3>
	 * <h3 class="zh-CN">从给定类中解析泛型类型数组。</h3>
	 *
	 * @param clazz <span class="en-US">Class instance</span>
	 *              <span class="zh-CN">类实例</span>
	 * @return <span class="en-US">The parsed array of generic types. If it does not contain generic information, an empty array of length 0 is returned.</span>
	 * <span class="zh-CN">解析的泛型类型数组，如果不包含泛型信息则返回长度为0的空数组</span>
	 */
	public static Class<?>[] componentTypes(final Class<?> clazz) {
		if (clazz == null) {
			return new Class<?>[0];
		}
		return parseTypeParameters(clazz, new HashMap<>());
	}

	/**
	 * <h3 class="en-US">Build a nice qualified name for an array: component type class name + "[]".</h3>
	 * <h3 class="zh-CN">为数组建立一个高质量的限定名称：组件类型类名+“[]”。</h3>
	 *
	 * @param clazz <span class="en-US">the array class</span>
	 *              <span class="zh-CN">数组类</span>
	 * @return <span class="en-US">a qualified name for the array class</span>
	 * <span class="zh-CN">数组类的限定名称</span>
	 */
	private static String getQualifiedNameForArray(final Class<?> clazz) {
		Class<?> currentClass = clazz;
		StringBuilder buffer = new StringBuilder();
		while (currentClass.isArray()) {
			currentClass = currentClass.getComponentType();
			buffer.append(ClassUtils.ARRAY_SUFFIX);
		}
		buffer.insert(0, currentClass.getName());
		return buffer.toString();
	}

	/**
	 * <h3 class="en-US">Parse an array of generic types from the given class.</h3>
	 * <h3 class="zh-CN">从给定类中解析泛型类型数组。</h3>
	 *
	 * @param clazz        <span class="en-US">Class instance</span>
	 *                     <span class="zh-CN">类实例</span>
	 * @param typeMappings <span class="en-US">Mapping table of class instances and generic definition names</span>
	 *                     <span class="zh-CN">类实例与泛型定义名称的映射表</span>
	 * @return <span class="en-US">The parsed array of generic types. If it does not contain generic information, an empty array of length 0 is returned.</span>
	 * <span class="zh-CN">解析的泛型类型数组，如果不包含泛型信息则返回长度为0的空数组</span>
	 */
	private static Class<?>[] parseTypeParameters(@Nonnull final Class<?> clazz,
	                                              @Nonnull final Map<String, Class<?>> typeMappings) {
		Type genericType = clazz.getGenericSuperclass();
		if (!ObjectUtils.nullSafeEquals(genericType, Object.class)) {
			if (genericType instanceof ParameterizedType) {
				Type[] actualTypes = ((ParameterizedType) genericType).getActualTypeArguments();
				if (actualTypes.length != 0) {
					TypeVariable<?>[] typeVariables = clazz.getSuperclass().getTypeParameters();
					int index = 0;
					for (Type type : actualTypes) {
						if (type instanceof Class<?>) {
							typeMappings.put(typeVariables[index].getTypeName(), (Class<?>) type);
						}
						index++;
					}
				}
			}
			return parseTypeParameters(clazz.getSuperclass(), typeMappings);
		}
		TypeVariable<?>[] typeVariables = clazz.getTypeParameters();
		if (typeVariables.length != 0) {
			int index = 0;
			Class<?>[] componentTypes = new Class[typeVariables.length];
			for (TypeVariable<?> typeVariable : typeVariables) {
				componentTypes[index] = typeMappings.get(typeVariable.getTypeName());
				index++;
			}
			return componentTypes;
		}
		return new Class<?>[0];
	}
}
