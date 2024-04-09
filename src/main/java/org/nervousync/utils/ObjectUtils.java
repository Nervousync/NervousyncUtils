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

import org.nervousync.commons.Globals;

import java.lang.reflect.*;
import java.util.Arrays;
import java.util.Optional;

/**
 * <h2 class="en-US">Object Operate Utilities</h2>
 * <h2 class="zh-CN">对象操作工具集</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.4 $ $Date: Jan 13, 2010 16:26:58 $
 */
public final class ObjectUtils {
	/**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(ObjectUtils.class);
	/**
	 * <span class="en-US">Constant value of array start character</span>
	 * <span class="zh-CN">数组起始字符常量值</span>
	 */
	private static final String ARRAY_START = "[";
	/**
	 * <span class="en-US">Constant value of array end character</span>
	 * <span class="zh-CN">数组终止字符常量值</span>
	 */
	private static final String ARRAY_END = "]";
	/**
	 * <span class="en-US">Constant value of array separator character</span>
	 * <span class="zh-CN">数组元素分割字符常量值</span>
	 */
	private static final String ARRAY_ELEMENT_SEPARATOR = ", ";

	/**
	 * <h3 class="en-US">Private constructor for ObjectUtils</h3>
	 * <h3 class="zh-CN">对象操作工具集的私有构造方法</h3>
	 */
	private ObjectUtils() {
	}

	/**
	 * <h3 class="en-US">Create a object instance by invoke non-args constructor method</h3>
	 * <h3 class="zh-CN">通过调用无参构造函数方法创建对象实例</h3>
	 *
	 * @param <T>   <span class="en-US">define class</span>
	 *              <span class="zh-CN">定义类</span>
	 * @param clazz <span class="en-US">define class</span>
	 *              <span class="zh-CN">定义类</span>
	 * @return <span class="en-US">Created object instance</span>
	 * <span class="zh-CN">创建的对象实例</span>
	 */
	public static <T> T newInstance(final Class<T> clazz) {
		return newInstance(clazz, new Object[0]);
	}

	/**
	 * <h3 class="en-US">Create a object instance by invoke constructor method as given parameter values</h3>
	 * <h3 class="zh-CN">通过给定参数值作为参数来调用构造方法创建对象实例</h3>
	 *
	 * @param <T>         <span class="en-US">define class</span>
	 *                    <span class="zh-CN">定义类</span>
	 * @param clazz       <span class="en-US">define class</span>
	 *                    <span class="zh-CN">定义类</span>
	 * @param paramValues <span class="en-US">Parameter values</span>
	 *                    <span class="zh-CN">参数值</span>
	 * @return <span class="en-US">Created object instance</span>
	 * <span class="zh-CN">创建的对象实例</span>
	 */
	public static <T> T newInstance(final Class<T> clazz, final Object[] paramValues) {
		if (clazz == null) {
			return null;
		}
		Constructor<T> constructor;
		try {
			if (paramValues == null || paramValues.length == 0) {
				constructor = ReflectionUtils.findConstructor(clazz);
				if (!Modifier.isPublic(clazz.getModifiers()) || !ReflectionUtils.publicMember(constructor)) {
					ReflectionUtils.makeAccessible(constructor);
				}
				return constructor.newInstance();
			} else {
				Class<?>[] paramTypes = new Class[paramValues.length];
				for (int i = 0; i < paramValues.length; i++) {
					paramTypes[i] = paramValues[i].getClass();
				}
				constructor = ReflectionUtils.findConstructor(clazz, paramTypes);
				if (!Modifier.isPublic(clazz.getModifiers()) || !ReflectionUtils.publicMember(constructor)) {
					ReflectionUtils.makeAccessible(constructor);
				}
				return constructor.newInstance(paramValues);
			}
		} catch (SecurityException | NoSuchMethodException | InstantiationException
		         | IllegalAccessException | InvocationTargetException e) {
			LOGGER.error("Create_Instance_Object_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Create a proxy object instance</h3>
	 * <h3 class="zh-CN">创建代理对象实例</h3>
	 *
	 * @param <T>               <span class="en-US">define class</span>
	 *                          <span class="zh-CN">定义类</span>
	 * @param clazz             <span class="en-US">define class</span>
	 *                          <span class="zh-CN">定义类</span>
	 * @param methodInterceptor <span class="en-US">method interceptor instance</span>
	 *                          <span class="zh-CN">方法拦截器实例</span>
	 * @return <span class="en-US">Created proxy object instance</span>
	 * <span class="zh-CN">创建的代理对象实例</span>
	 */
	public static <T> T newInstance(final Class<T> clazz, final InvocationHandler methodInterceptor) {
		return newInstance(clazz, new Class[]{clazz}, methodInterceptor);
	}

	/**
	 * <h3 class="en-US">Create a proxy object instance</h3>
	 * <h3 class="zh-CN">创建代理对象实例</h3>
	 *
	 * @param <T>               <span class="en-US">define class</span>
	 *                          <span class="zh-CN">定义类</span>
	 * @param clazz             <span class="en-US">define class</span>
	 *                          <span class="zh-CN">定义类</span>
	 * @param interfaceClasses  <span class="en-US">Interface class array</span>
	 *                          <span class="zh-CN">接口类数组</span>
	 * @param invocationHandler <span class="en-US">method interceptor instance</span>
	 *                          <span class="zh-CN">方法拦截器实例</span>
	 * @return <span class="en-US">Created proxy object instance</span>
	 * <span class="zh-CN">创建的代理对象实例</span>
	 */
	public static <T> T newInstance(final Class<T> clazz, final Class<?>[] interfaceClasses,
	                                final InvocationHandler invocationHandler) {
		if (clazz == null || invocationHandler == null) {
			return newInstance(clazz);
		}
		Class<?>[] interfaces;
		if (interfaceClasses == null || interfaceClasses.length == 0) {
			interfaces = new Class[]{clazz};
		} else {
			interfaces = interfaceClasses;
		}
		return clazz.cast(Proxy.newProxyInstance(clazz.getClassLoader(), interfaces, invocationHandler));
	}

	/**
	 * <h3 class="en-US">Create an array of generic objects</h3>
	 * <h3 class="zh-CN">创建泛型对象数组</h3>
	 *
	 * @param <T>    <span class="en-US">define class</span>
	 *               <span class="zh-CN">定义类</span>
	 * @param clazz  <span class="en-US">define class</span>
	 *               <span class="zh-CN">定义类</span>
	 * @return <span class="en-US">Created object array instance</span>
	 * <span class="zh-CN">创建的对象数组</span>
	 */
	public static <T> T[] newArray(final Class<T> clazz) {
		return newArray(clazz, Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * <h3 class="en-US">Create an array of generic objects</h3>
	 * <h3 class="zh-CN">创建泛型对象数组</h3>
	 *
	 * @param <T>    <span class="en-US">define class</span>
	 *               <span class="zh-CN">定义类</span>
	 * @param clazz  <span class="en-US">define class</span>
	 *               <span class="zh-CN">定义类</span>
	 * @param length <span class="en-US">Array length</span>
	 *               <span class="zh-CN">数组长度</span>
	 * @return <span class="en-US">Created object array instance</span>
	 * <span class="zh-CN">创建的对象数组</span>
	 */
	@SuppressWarnings("unchecked")
	public static <T> T[] newArray(final Class<T> clazz, final int length) {
		return (T[]) Array.newInstance(clazz, length < 0 ? Globals.INITIALIZE_INT_VALUE : length);
	}

	/**
	 * <h3 class="en-US">Return whether the given object is empty: that is, <code>null</code> or a collection of zero-length.</h3>
	 * <h3 class="zh-CN">返回给定对象是否为空：即 <code>null</code> 或长度为零的集合。</h3>
	 *
	 * @param object <span class="en-US">the object to check</span>
	 *               <span class="zh-CN">检查对象</span>
	 * @return <span class="en-US">whether the given object is <code>null</code> or collection is empty</span>
	 * <span class="zh-CN">给定对象是否为 <code>null</code> 或集合是否为空</span>
	 */
	public static boolean isNull(final Object object) {
		if (object == null) {
			return Boolean.TRUE;
		}
		if (object.getClass().isArray()) {
			return (Array.getLength(object) == 0);
		} else {
			if (object instanceof String) {
				return (((String) object).isEmpty());
			}
		}
		return Boolean.FALSE;
	}
	//---------------------------------------------------------------------
	// Convenience methods for content-based equality/hash-code handling
	//---------------------------------------------------------------------

	/**
	 * <h3 class="en-US">Determine if the given objects are equal.</h3>
	 * <span class="en-US">
	 * Returning <code>Boolean.TRUE</code> if both are <code>null</code>
	 * or <code>Boolean.FALSE</code> if only one is <code>null</code>.
	 * Compares arrays with <code>Arrays.equals</code>, performing an equality
	 * check based on the array elements rather than the array reference.
	 * </span>
	 * <h3 class="zh-CN">确定给定的对象是否相等。</h3>
	 * <span class="zh-CN">
	 * 如果两者都为 <code>null</code>，则返回 <code>Boolean.TRUE</code>；
	 * 如果只有一个为 <code>null</code>，则返回 <code>Boolean.FALSE</code>。
	 * 将数组与 Arrays.equals 进行比较，根据数组元素而不是数组引用执行相等性检查。
	 * </span>
	 *
	 * @param o1 <span class="en-US">first Object to compare</span>
	 *           <span class="zh-CN">第一个要比较的对象</span>
	 * @param o2 <span class="en-US">second Object to compare</span>
	 *           <span class="zh-CN">第二个要比较的对象</span>
	 * @return <span class="en-US">whether the given objects are equal</span>
	 * <span class="zh-CN">给定的对象是否相等</span>
	 * @see java.util.Arrays#equals
	 */
	public static boolean nullSafeEquals(final Object o1, final Object o2) {
		if (o1 == o2) {
			return Boolean.TRUE;
		}
		if (o1 == null || o2 == null) {
			return Boolean.FALSE;
		}
		if (o1.equals(o2)) {
			return Boolean.TRUE;
		}
		if (o1.getClass().isArray() && o2.getClass().isArray()) {
			if (o1 instanceof Object[] && o2 instanceof Object[]) {
				return Arrays.equals((Object[]) o1, (Object[]) o2);
			}
			if (o1 instanceof boolean[] && o2 instanceof boolean[]) {
				return Arrays.equals((boolean[]) o1, (boolean[]) o2);
			}
			if (o1 instanceof byte[] && o2 instanceof byte[]) {
				return Arrays.equals((byte[]) o1, (byte[]) o2);
			}
			if (o1 instanceof char[] && o2 instanceof char[]) {
				return Arrays.equals((char[]) o1, (char[]) o2);
			}
			if (o1 instanceof double[] && o2 instanceof double[]) {
				return Arrays.equals((double[]) o1, (double[]) o2);
			}
			if (o1 instanceof float[] && o2 instanceof float[]) {
				return Arrays.equals((float[]) o1, (float[]) o2);
			}
			if (o1 instanceof int[] && o2 instanceof int[]) {
				return Arrays.equals((int[]) o1, (int[]) o2);
			}
			if (o1 instanceof long[] && o2 instanceof long[]) {
				return Arrays.equals((long[]) o1, (long[]) o2);
			}
			if (o1 instanceof short[] && o2 instanceof short[]) {
				return Arrays.equals((short[]) o1, (short[]) o2);
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Return as hash code for the given object; typically the value of <code>Object#hashCode()</code>.</h3>
	 * <span class="en-US">
	 * If the object is an array, this method will delegate to any of the <code>nullSafeHashCode</code>
	 * methods for arrays in this class.
	 * If the object is <code>null</code>, this method returns 0.
	 * </span>
	 * <h3 class="zh-CN">返回给定对象的哈希码；通常是 <code>Object#hashCode()</code> 的值。</h3>
	 * <span class="zh-CN">
	 * 如果对象是数组，则此方法将委托给此类中数组的任何 <code>ObjectUtils#nullSafeHashCode</code> 方法。
	 * 如果对象为 <code>null</code>，则此方法返回 0。
	 * </span>
	 *
	 * @param obj <span class="en-US">given object</span>
	 *            <span class="zh-CN">给定对象</span>
	 * @return <span class="en-US">object hash code</span>
	 * <span class="zh-CN">对象哈希值</span>
	 * @see ObjectUtils#nullSafeHashCode(Object[])
	 * @see ObjectUtils#nullSafeHashCode(boolean[])
	 * @see ObjectUtils#nullSafeHashCode(byte[])
	 * @see ObjectUtils#nullSafeHashCode(char[])
	 * @see ObjectUtils#nullSafeHashCode(double[])
	 * @see ObjectUtils#nullSafeHashCode(float[])
	 * @see ObjectUtils#nullSafeHashCode(int[])
	 * @see ObjectUtils#nullSafeHashCode(long[])
	 * @see ObjectUtils#nullSafeHashCode(short[])
	 */
	public static int nullSafeHashCode(final Object obj) {
		if (obj == null) {
			return 0;
		}
		if (obj.getClass().isArray()) {
			if (obj instanceof Object[]) {
				return nullSafeHashCode((Object[]) obj);
			}
			if (obj instanceof boolean[]) {
				return nullSafeHashCode((boolean[]) obj);
			}
			if (obj instanceof byte[]) {
				return nullSafeHashCode((byte[]) obj);
			}
			if (obj instanceof char[]) {
				return nullSafeHashCode((char[]) obj);
			}
			if (obj instanceof double[]) {
				return nullSafeHashCode((double[]) obj);
			}
			if (obj instanceof float[]) {
				return nullSafeHashCode((float[]) obj);
			}
			if (obj instanceof int[]) {
				return nullSafeHashCode((int[]) obj);
			}
			if (obj instanceof long[]) {
				return nullSafeHashCode((long[]) obj);
			}
			if (obj instanceof short[]) {
				return nullSafeHashCode((short[]) obj);
			}
		}
		return obj.hashCode();
	}

	/**
	 * <h3 class="en-US">Return a hash code based on the contents of the specified array.</h3>
	 * <span class="en-US">If argument array is <code>null</code>, this method returns 0.</span>
	 * <h3 class="zh-CN">根据指定数组的内容返回哈希码。</h3>
	 * <span class="zh-CN">如果参数 array 为<code>null</code>，则此方法返回0。</span>
	 *
	 * @param array <span class="en-US">specified array</span>
	 *              <span class="zh-CN">指定数组</span>
	 * @return <span class="en-US">object hash code</span>
	 * <span class="zh-CN">对象哈希值</span>
	 */
	public static int nullSafeHashCode(final Object[] array) {
		if (array == null) {
			return 0;
		}
		int hash = Globals.INITIALIZE_INT_VALUE;
		for (Object anArray : array) {
			hash = Globals.MULTIPLIER * hash + nullSafeHashCode(anArray);
		}
		return hash;
	}

	/**
	 * <h3 class="en-US">Return a hash code based on the contents of the specified array.</h3>
	 * <span class="en-US">If argument array  is <code>null</code>, this method returns 0.</span>
	 * <h3 class="zh-CN">根据指定数组的内容返回哈希码。</h3>
	 * <span class="zh-CN">如果 参数 array  为<code>null</code>，则此方法返回0。</span>
	 *
	 * @param array <span class="en-US">specified array</span>
	 *              <span class="zh-CN">指定数组</span>
	 * @return <span class="en-US">object hash code</span>
	 * <span class="zh-CN">对象哈希值</span>
	 */
	public static int nullSafeHashCode(final boolean[] array) {
		if (array == null) {
			return 0;
		}
		int hash = Globals.INITIALIZE_INT_VALUE;
		for (boolean bool : array) {
			hash = Globals.MULTIPLIER * hash + Boolean.hashCode(bool);
		}
		return hash;
	}

	/**
	 * <h3 class="en-US">Return a hash code based on the contents of the specified array.</h3>
	 * <span class="en-US">If byte array is <code>null</code>, this method returns 0.</span>
	 * <h3 class="zh-CN">根据指定数组的内容返回哈希码。</h3>
	 * <span class="zh-CN">如果字节数组为<code>null</code>，则此方法返回0。</span>
	 *
	 * @param array <span class="en-US">specified array</span>
	 *              <span class="zh-CN">指定数组</span>
	 * @return <span class="en-US">object hash code</span>
	 * <span class="zh-CN">对象哈希值</span>
	 */
	public static int nullSafeHashCode(final byte[] array) {
		if (array == null) {
			return 0;
		}
		int hash = Globals.INITIALIZE_INT_VALUE;
		for (byte b : array) {
			hash = Globals.MULTIPLIER * hash + b;
		}
		return hash;
	}

	/**
	 * <h3 class="en-US">Return a hash code based on the contents of the specified array.</h3>
	 * <span class="en-US">If argument array is <code>null</code>, this method returns 0.</span>
	 * <h3 class="zh-CN">根据指定数组的内容返回哈希码。</h3>
	 * <span class="zh-CN">如果参数 array 为<code>null</code>，则此方法返回0。</span>
	 *
	 * @param array <span class="en-US">specified array</span>
	 *              <span class="zh-CN">指定数组</span>
	 * @return <span class="en-US">object hash code</span>
	 * <span class="zh-CN">对象哈希值</span>
	 */
	public static int nullSafeHashCode(final char[] array) {
		if (array == null) {
			return 0;
		}
		int hash = Globals.INITIALIZE_INT_VALUE;
		for (char c : array) {
			hash = Globals.MULTIPLIER * hash + c;
		}
		return hash;
	}

	/**
	 * <h3 class="en-US">Return a hash code based on the contents of the specified array.</h3>
	 * <span class="en-US">If argument array is <code>null</code>, this method returns 0.</span>
	 * <h3 class="zh-CN">根据指定数组的内容返回哈希码。</h3>
	 * <span class="zh-CN">如果参数 array 为<code>null</code>，则此方法返回0。</span>
	 *
	 * @param array <span class="en-US">specified array</span>
	 *              <span class="zh-CN">指定数组</span>
	 * @return <span class="en-US">object hash code</span>
	 * <span class="zh-CN">对象哈希值</span>
	 */
	public static int nullSafeHashCode(final double[] array) {
		if (array == null) {
			return 0;
		}
		int hash = Globals.INITIALIZE_INT_VALUE;
		for (double d : array) {
			hash = Globals.MULTIPLIER * hash + Double.hashCode(d);
		}
		return hash;
	}

	/**
	 * <h3 class="en-US">Return a hash code based on the contents of the specified array.</h3>
	 * <span class="en-US">If argument array is <code>null</code>, this method returns 0.</span>
	 * <h3 class="zh-CN">根据指定数组的内容返回哈希码。</h3>
	 * <span class="zh-CN">如果参数 array 为<code>null</code>，则此方法返回0。</span>
	 *
	 * @param array <span class="en-US">specified array</span>
	 *              <span class="zh-CN">指定数组</span>
	 * @return <span class="en-US">object hash code</span>
	 * <span class="zh-CN">对象哈希值</span>
	 */
	public static int nullSafeHashCode(final float[] array) {
		if (array == null) {
			return 0;
		}
		int hash = Globals.INITIALIZE_INT_VALUE;
		for (float f : array) {
			hash = Globals.MULTIPLIER * hash + Float.hashCode(f);
		}
		return hash;
	}

	/**
	 * <h3 class="en-US">Return a hash code based on the contents of the specified array.</h3>
	 * <span class="en-US">If argument array is <code>null</code>, this method returns 0.</span>
	 * <h3 class="zh-CN">根据指定数组的内容返回哈希码。</h3>
	 * <span class="zh-CN">如果参数 array 为<code>null</code>，则此方法返回0。</span>
	 *
	 * @param array <span class="en-US">specified array</span>
	 *              <span class="zh-CN">指定数组</span>
	 * @return <span class="en-US">object hash code</span>
	 * <span class="zh-CN">对象哈希值</span>
	 */
	public static int nullSafeHashCode(final int[] array) {
		if (array == null) {
			return 0;
		}
		int hash = Globals.INITIALIZE_INT_VALUE;
		for (int i : array) {
			hash = Globals.MULTIPLIER * hash + Integer.hashCode(i);
		}
		return hash;
	}

	/**
	 * <h3 class="en-US">Return a hash code based on the contents of the specified array.</h3>
	 * <span class="en-US">If argument array is <code>null</code>, this method returns 0.</span>
	 * <h3 class="zh-CN">根据指定数组的内容返回哈希码。</h3>
	 * <span class="zh-CN">如果参数 array 为<code>null</code>，则此方法返回0。</span>
	 *
	 * @param array <span class="en-US">specified array</span>
	 *              <span class="zh-CN">指定数组</span>
	 * @return <span class="en-US">object hash code</span>
	 * <span class="zh-CN">对象哈希值</span>
	 */
	public static int nullSafeHashCode(final long[] array) {
		if (array == null) {
			return 0;
		}
		int hash = Globals.INITIALIZE_INT_VALUE;
		for (long l : array) {
			hash = Globals.MULTIPLIER * hash + Long.hashCode(l);
		}
		return hash;
	}

	/**
	 * <h3 class="en-US">Return a hash code based on the contents of the specified array.</h3>
	 * <span class="en-US">If argument array is <code>null</code>, this method returns 0.</span>
	 * <h3 class="zh-CN">根据指定数组的内容返回哈希码。</h3>
	 * <span class="zh-CN">如果参数 array 为<code>null</code>，则此方法返回0。</span>
	 *
	 * @param array <span class="en-US">specified array</span>
	 *              <span class="zh-CN">指定数组</span>
	 * @return <span class="en-US">object hash code</span>
	 * <span class="zh-CN">对象哈希值</span>
	 */
	public static int nullSafeHashCode(final short[] array) {
		if (array == null) {
			return 0;
		}
		int hash = Globals.INITIALIZE_INT_VALUE;
		for (short s : array) {
			hash = Globals.MULTIPLIER * hash + Short.hashCode(s);
		}
		return hash;
	}

	/**
	 * <h3 class="en-US">Determine the class name for the given object.</h3>
	 * <span class="en-US">Returns empty string if argument obj is <code>null</code>.</span>
	 * <h3 class="zh-CN">确定给定对象的类名。</h3>
	 * <span class="zh-CN">如果参数 obj 为 <code>null</code>，则返回空字符串。</span>
	 *
	 * @param obj <span class="en-US">the object to introspect (maybe <code>null</code>)</span>
	 *            <span class="zh-CN">要获取类名的对象（可能<code>null</code>）</span>
	 * @return <span class="en-US">the corresponding class name</span>
	 * <span class="zh-CN">对应的类名</span>
	 */
	public static String nullSafeClassName(final Object obj) {
		return Optional.ofNullable(obj)
				.map(object -> nullSafeClassName(object.getClass()))
				.orElse(Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * <h3 class="en-US">Determine the class name for the given object.</h3>
	 * <span class="en-US">Returns empty string if argument clazz is <code>null</code>.</span>
	 * <h3 class="zh-CN">确定给定对象的类名。</h3>
	 * <span class="zh-CN">如果参数 clazz 为 <code>null</code>，则返回空字符串。</span>
	 *
	 * @param clazz <span class="en-US">the object to introspect (maybe <code>null</code>)</span>
	 *              <span class="zh-CN">要获取类名的对象（可能<code>null</code>）</span>
	 * @return <span class="en-US">the corresponding class name</span>
	 * <span class="zh-CN">对应的类名</span>
	 */
	public static String nullSafeClassName(final Class<?> clazz) {
		return Optional.ofNullable(clazz)
				.map(Class::getName)
				.orElse(Globals.DEFAULT_VALUE_STRING);
	}
	//---------------------------------------------------------------------
	// Convenience methods for toString output
	//---------------------------------------------------------------------

	/**
	 * <h3 class="en-US">Return a String representation of the specified Object.</h3>
	 * <span class="en-US">
	 * Builds a String representation of the contents in case of an array.
	 * Returns empty string if argument obj is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定对象的字符串表示形式。</h3>
	 * <span class="zh-CN">如果是数组，则构建内容的字符串表示形式。如果参数 obj 为 <code>null</code>，则返回空字符串。</span>
	 *
	 * @param obj <span class="en-US">the object to build a String representation for</span>
	 *            <span class="zh-CN">为其构建字符串表示的对象</span>
	 * @return <span class="en-US">a String representation of argument obj</span>
	 * <span class="zh-CN">参数 obj 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final Object obj) {
		if (obj == null) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		if (obj instanceof String) {
			return (String) obj;
		}
		if (ClassUtils.isPrimitiveArray(obj.getClass())) {
			if (obj instanceof boolean[]) {
				return nullSafeToString((boolean[]) obj);
			}
			if (obj instanceof byte[]) {
				return nullSafeToString((byte[]) obj);
			}
			if (obj instanceof char[]) {
				return nullSafeToString((char[]) obj);
			}
			if (obj instanceof double[]) {
				return nullSafeToString((double[]) obj);
			}
			if (obj instanceof float[]) {
				return nullSafeToString((float[]) obj);
			}
			if (obj instanceof int[]) {
				return nullSafeToString((int[]) obj);
			}
			if (obj instanceof long[]) {
				return nullSafeToString((long[]) obj);
			}
			if (obj instanceof short[]) {
				return nullSafeToString((short[]) obj);
			}
			return ARRAY_START + ARRAY_END;
		} else if (obj instanceof Class<?>[]) {
			return nullSafeToString((Class<?>[]) obj);
		} else if (obj.getClass().isArray()) {
			return nullSafeToString(CollectionUtils.toArray(obj));
		} else if (obj.getClass().isPrimitive()) {
			return Optional.ofNullable(ClassUtils.primitiveWrapper(obj.getClass()))
					.map(wrapperClass -> ReflectionUtils.findMethod(wrapperClass, "toString", new Class[]{obj.getClass()}))
					.map(method -> (String) ReflectionUtils.invokeMethod(method, null, new Object[]{obj}))
					.orElse(Globals.DEFAULT_VALUE_STRING);
		} else {
			return obj.toString();
		}
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array <span class="en-US">the array to build a String representation for</span>
	 *              <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final Class<?>[] array) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements.
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final Class<?>[] array, final boolean processCompletion) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the argument separator characters.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。
	 * 相邻元素由参数 separator 字符分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array     <span class="en-US">the array to build a String representation for</span>
	 *                  <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator <span class="en-US">array separator character</span>
	 *                  <span class="zh-CN">数组元素分割字符</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final Class<?>[] array, final String separator) {
		return nullSafeToString(array, separator, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * Adjacent elements are separated by the argument separator characters.
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由参数 separator 字符分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator         <span class="en-US">array separator character</span>
	 *                          <span class="zh-CN">数组元素分割字符</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final Class<?>[] array, final String separator,
	                                      final boolean processCompletion) {
		return nullSafeToString(CollectionUtils.toArray(array), separator, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Returns empty string if argument array  is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果 参数 array  为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array <span class="en-US">the array to build a String representation for</span>
	 *              <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array  的字符串表示形式</span>
	 */
	public static String nullSafeToString(final boolean[] array) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements.
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array  is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果 参数 array  为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array  的字符串表示形式</span>
	 */
	public static String nullSafeToString(final boolean[] array, final boolean processCompletion) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the argument separator characters.
	 * Returns empty string if argument array  is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。
	 * 相邻元素由参数 separator 字符分隔。
	 * 如果 参数 array  为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array     <span class="en-US">the array to build a String representation for</span>
	 *                  <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator <span class="en-US">array separator character</span>
	 *                  <span class="zh-CN">数组元素分割字符</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array  的字符串表示形式</span>
	 */
	public static String nullSafeToString(final boolean[] array, final String separator) {
		return nullSafeToString(array, separator, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * Adjacent elements are separated by the argument separator characters.
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array  is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由参数 separator 字符分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果 参数 array  为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator         <span class="en-US">array separator character</span>
	 *                          <span class="zh-CN">数组元素分割字符</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array  的字符串表示形式</span>
	 */
	public static String nullSafeToString(final boolean[] array, final String separator,
	                                      final boolean processCompletion) {
		return nullSafeToString(CollectionUtils.toArray(array), separator, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array <span class="en-US">the array to build a String representation for</span>
	 *              <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @return <span class="en-US">a String representation of byte array</span>
	 * <span class="zh-CN">字节数组的字符串表示形式</span>
	 */
	public static String nullSafeToString(final byte[] array) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements.
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of byte array</span>
	 * <span class="zh-CN">字节数组的字符串表示形式</span>
	 */
	public static String nullSafeToString(final byte[] array, final boolean processCompletion) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the argument separator characters.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。
	 * 相邻元素由参数 separator 字符分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array     <span class="en-US">the array to build a String representation for</span>
	 *                  <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator <span class="en-US">array separator character</span>
	 *                  <span class="zh-CN">数组元素分割字符</span>
	 * @return <span class="en-US">a String representation of byte array</span>
	 * <span class="zh-CN">字节数组的字符串表示形式</span>
	 */
	public static String nullSafeToString(final byte[] array, final String separator) {
		return nullSafeToString(array, separator, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * Adjacent elements are separated by the argument separator characters.
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由参数 separator 字符分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator         <span class="en-US">array separator character</span>
	 *                          <span class="zh-CN">数组元素分割字符</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of byte array</span>
	 * <span class="zh-CN">字节数组的字符串表示形式</span>
	 */
	public static String nullSafeToString(final byte[] array, final String separator,
	                                      final boolean processCompletion) {
		return nullSafeToString(CollectionUtils.toArray(array), separator, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array <span class="en-US">the array to build a String representation for</span>
	 *              <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final char[] array) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements.
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final char[] array, final boolean processCompletion) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the argument separator characters.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。
	 * 相邻元素由参数 separator 字符分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array     <span class="en-US">the array to build a String representation for</span>
	 *                  <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator <span class="en-US">array separator character</span>
	 *                  <span class="zh-CN">数组元素分割字符</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final char[] array, final String separator) {
		return nullSafeToString(array, separator, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * Adjacent elements are separated by the argument separator characters.
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由参数 separator 字符分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator         <span class="en-US">array separator character</span>
	 *                          <span class="zh-CN">数组元素分割字符</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final char[] array, final String separator,
	                                      final boolean processCompletion) {
		return nullSafeToString(CollectionUtils.toArray(array), separator, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array <span class="en-US">the array to build a String representation for</span>
	 *              <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final double[] array) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements.
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final double[] array, final boolean processCompletion) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the argument separator characters.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。
	 * 相邻元素由参数 separator 字符分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array     <span class="en-US">the array to build a String representation for</span>
	 *                  <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator <span class="en-US">array separator character</span>
	 *                  <span class="zh-CN">数组元素分割字符</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final double[] array, final String separator) {
		return nullSafeToString(array, separator, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * Adjacent elements are separated by the argument separator characters.
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由参数 separator 字符分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator         <span class="en-US">array separator character</span>
	 *                          <span class="zh-CN">数组元素分割字符</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final double[] array, final String separator,
	                                      final boolean processCompletion) {
		return nullSafeToString(CollectionUtils.toArray(array), separator, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array <span class="en-US">the array to build a String representation for</span>
	 *              <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final float[] array) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements.
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果 argument processCompletion为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final float[] array, final boolean processCompletion) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the argument separator characters.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。
	 * 相邻元素由参数 separator 字符分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array     <span class="en-US">the array to build a String representation for</span>
	 *                  <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator <span class="en-US">array separator character</span>
	 *                  <span class="zh-CN">数组元素分割字符</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final float[] array, final String separator) {
		return nullSafeToString(array, separator, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * Adjacent elements are separated by the argument separator characters.
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由参数 separator 字符分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator         <span class="en-US">array separator character</span>
	 *                          <span class="zh-CN">数组元素分割字符</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final float[] array, final String separator,
	                                      final boolean processCompletion) {
		return nullSafeToString(CollectionUtils.toArray(array), separator, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array <span class="en-US">the array to build a String representation for</span>
	 *              <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final int[] array) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements.
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final int[] array, final boolean processCompletion) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the argument separator characters.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。
	 * 相邻元素由参数 separator 字符分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array     <span class="en-US">the array to build a String representation for</span>
	 *                  <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator <span class="en-US">array separator character</span>
	 *                  <span class="zh-CN">数组元素分割字符</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final int[] array, final String separator) {
		return nullSafeToString(array, separator, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * Adjacent elements are separated by the argument separator characters.
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由参数 separator 字符分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator         <span class="en-US">array separator character</span>
	 *                          <span class="zh-CN">数组元素分割字符</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final int[] array, final String separator,
	                                      final boolean processCompletion) {
		return nullSafeToString(CollectionUtils.toArray(array), separator, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array <span class="en-US">the array to build a String representation for</span>
	 *              <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final long[] array) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements.
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final long[] array, final boolean processCompletion) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the argument separator characters.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。
	 * 相邻元素由参数 separator 字符分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array     <span class="en-US">the array to build a String representation for</span>
	 *                  <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator <span class="en-US">array separator character</span>
	 *                  <span class="zh-CN">数组元素分割字符</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final long[] array, final String separator) {
		return nullSafeToString(array, separator, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * Adjacent elements are separated by the argument separator characters.
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由参数 separator 字符分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator         <span class="en-US">array separator character</span>
	 *                          <span class="zh-CN">数组元素分割字符</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final long[] array, final String separator,
	                                      final boolean processCompletion) {
		return nullSafeToString(CollectionUtils.toArray(array), separator, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array <span class="en-US">the array to build a String representation for</span>
	 *              <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final short[] array) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements.
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final short[] array, final boolean processCompletion) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the argument separator characters.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。
	 * 相邻元素由参数 separator 字符分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array     <span class="en-US">the array to build a String representation for</span>
	 *                  <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator <span class="en-US">array separator character</span>
	 *                  <span class="zh-CN">数组元素分割字符</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final short[] array, final String separator) {
		return nullSafeToString(array, separator, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * Adjacent elements are separated by the argument separator characters.
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由参数 separator 字符分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator         <span class="en-US">array separator character</span>
	 *                          <span class="zh-CN">数组元素分割字符</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final short[] array, final String separator,
	                                      final boolean processCompletion) {
		return nullSafeToString(CollectionUtils.toArray(array), separator, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array <span class="en-US">the array to build a String representation for</span>
	 *              <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final Object[] array) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements.
	 * Adjacent elements are separated by the characters <code>", "</code> (a comma followed by a space).
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由字符 <code>", "</code>（逗号后跟空格）分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final Object[] array, final boolean processCompletion) {
		return nullSafeToString(array, ARRAY_ELEMENT_SEPARATOR, processCompletion);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * enclosed in brackets (<code>"[]"</code>).
	 * Adjacent elements are separated by the argument separator characters.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，括在中括号 (<code>"[]"</code>) 中。
	 * 相邻元素由参数 separator 字符分隔。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array     <span class="en-US">the array to build a String representation for</span>
	 *                  <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator <span class="en-US">array separator character</span>
	 *                  <span class="zh-CN">数组元素分割字符</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final Object[] array, final String separator) {
		return nullSafeToString(array, separator, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Return a String representation of the contents of the specified array.</h3>
	 * <span class="en-US">
	 * The String representation consists of a list of the array's elements,
	 * Adjacent elements are separated by the argument separator characters.
	 * Enclosed in brackets (<code>"[]"</code>) if argument processCompletion is <code>Boolean.TRUE</code>.
	 * Returns empty string if argument array is <code>null</code>.
	 * </span>
	 * <h3 class="zh-CN">返回指定数组内容的字符串表示形式。</h3>
	 * <span class="zh-CN">
	 * 字符串表示形式由数组元素列表组成，相邻元素由参数 separator 字符分隔。
	 * 如果参数 processCompletion 为 <code>Boolean.TRUE</code> 则括在中括号 (<code>"[]"</code>) 中。
	 * 如果参数 array 为 <code>null</code>，则返回空字符串
	 * </span>
	 *
	 * @param array             <span class="en-US">the array to build a String representation for</span>
	 *                          <span class="zh-CN">为其构建字符串表示的数组</span>
	 * @param separator         <span class="en-US">array separator character</span>
	 *                          <span class="zh-CN">数组元素分割字符</span>
	 * @param processCompletion <span class="en-US">Enclosed result in brackets (<code>"[]"</code>)</span>
	 *                          <span class="zh-CN">将结果括在中括号 (<code>"[]"</code>) 中</span>
	 * @return <span class="en-US">a String representation of argument array</span>
	 * <span class="zh-CN">参数 array 的字符串表示形式</span>
	 */
	public static String nullSafeToString(final Object[] array, final String separator,
	                                      final boolean processCompletion) {
		if (array == null || array.length == 0) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		StringBuilder stringBuilder = new StringBuilder();
		String split = StringUtils.isEmpty(separator) ? ARRAY_ELEMENT_SEPARATOR : separator;
		Arrays.asList(array).forEach(object -> stringBuilder.append(split).append(object));
		return processCompletion ? stringBuilderCompletion(stringBuilder) : stringBuilder.substring(split.length());
	}

	/**
	 * <h3 class="en-US">Insert array start character at index 0 and append array end character at end of the argument stringBuilder, and return the final result string.</h3>
	 * <h3 class="zh-CN">在索引 0 处插入数组起始字符，并在参数 stringBuilder 末尾附加数组结束字符，并返回最终结果字符串。</h3>
	 *
	 * @param stringBuilder <span class="en-US">the string builder will process for</span>
	 *                      <span class="zh-CN">将处理的字符串生成器</span>
	 * @return <span class="en-US">the final result string.</span>
	 * <span class="zh-CN">最终结果字符串</span>
	 */
	private static String stringBuilderCompletion(final StringBuilder stringBuilder) {
		stringBuilder.insert(ARRAY_ELEMENT_SEPARATOR.length(), ARRAY_START).append(ARRAY_END);
		return stringBuilder.substring(ARRAY_ELEMENT_SEPARATOR.length());
	}
}
