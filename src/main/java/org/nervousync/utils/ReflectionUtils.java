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

import java.lang.annotation.Annotation;
import java.lang.reflect.*;
import java.util.*;

/**
 * <h2 class="en-US">Reflection Operate Utilities</h2>
 * <h2 class="zh-CN">反射操作工具集</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.4 $ $Date: Jan 13, 2010 16:26:58 $
 */
public final class ReflectionUtils {
    /**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
     */
    private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(ReflectionUtils.class);

    /**
     * <h3 class="en-US">Private constructor for ReflectionUtils</h3>
     * <h3 class="zh-CN">反射操作工具集的私有构造方法</h3>
     */
    private ReflectionUtils() {
    }

    /**
     * <h3 class="en-US">Parse field name from getter/setter method name</h3>
     * <h3 class="zh-CN">从 getter/setter 方法名称解析字段名称</h3>
     *
     * @param methodName <span class="en-US">method name</span>
     *                   <span class="zh-CN">方法名称</span>
     * @return <span class="en-US">parsed field name</span>
     * <span class="zh-CN">解析的字段名称</span>
     */
    public static String fieldName(final String methodName) {
        String fieldName = null;

        if (methodName != null) {
            if (methodName.startsWith("get") || methodName.startsWith("set")) {
                fieldName = methodName.substring(3);
            } else if (methodName.startsWith("is")) {
                fieldName = methodName.substring(2);
            }
        }

        if (StringUtils.notBlank(fieldName)) {
            fieldName = StringUtils.uncapitalized(fieldName);
        }

        return fieldName;
    }

    /**
     * <h3 class="en-US">Find constructor method</h3>
     * <h3 class="zh-CN">查找构造方法</h3>
     *
     * @param <T>   <span class="en-US">Target class instance</span>
     *              <span class="zh-CN">目标类实例</span>
     * @param clazz <span class="en-US">Target class instance</span>
     *              <span class="zh-CN">目标类实例</span>
     * @return <span class="en-US">the constructor method</span>
     * <span class="zh-CN">构造方法</span>
     */
    public static <T> Constructor<T> findConstructor(final Class<T> clazz)
            throws SecurityException, NoSuchMethodException {
        return findConstructor(clazz, new Class[0]);
    }

    /**
     * <h3 class="en-US">Find constructor method</h3>
     * <h3 class="zh-CN">查找构造方法</h3>
     *
     * @param <T>        <span class="en-US">Target class instance</span>
     *                   <span class="zh-CN">目标类实例</span>
     * @param clazz      <span class="en-US">Target class instance</span>
     *                   <span class="zh-CN">目标类实例</span>
     * @param paramTypes <span class="en-US">the param type class array</span>
     *                   <span class="zh-CN">参数类型类数组</span>
     * @return <span class="en-US">the constructor method</span>
     * <span class="zh-CN">构造方法</span>
     */
    public static <T> Constructor<T> findConstructor(final Class<T> clazz, final Class<?>[] paramTypes)
            throws SecurityException, NoSuchMethodException {
        if (paramTypes == null || paramTypes.length == 0) {
            return clazz.getDeclaredConstructor();
        }
        return clazz.getDeclaredConstructor(paramTypes);
    }

    /**
     * <h3 class="en-US">Find field instance</h3>
     * <span class="en-US">
     * Attempt to find a field instance on the supplied argument clazz with the supplied <code>name</code>.
     * Searches all superclasses up to <code>Object</code>.
     * </span>
     * <h3 class="zh-CN">查找字段实例</h3>
     * <span class="zh-CN">
     * 尝试使用提供的字段名称在提供的参数 clazz 上查找属性反射对象。搜索所有超类直到 <code>Object</code>。
     * </span>
     *
     * @param clazz <span class="en-US">Target class instance</span>
     *              <span class="zh-CN">目标类实例</span>
     * @param name  <span class="en-US">the name of the field</span>
     *              <span class="zh-CN">字段名称</span>
     * @return <span class="en-US">the corresponding Field object, or <code>null</code> if not found</span>
     * <span class="zh-CN">相应的 Field 对象，如果未找到则为 <code>null</code></span>
     */
    public static Field findField(final Class<?> clazz, final String name) {
        return findField(clazz, name, null);
    }

    /**
     * <h3 class="en-US">Find field instance</h3>
     * <span class="en-US">
     * Attempt to find a field instance on the supplied argument clazz
     * with the supplied <code>name</code> and/or field type as argument fieldType.
     * Searches all superclasses up to <code>Object</code>.
     * </span>
     * <h3 class="zh-CN">查找字段实例</h3>
     * <span class="zh-CN">
     * 在给定的参数 clazz 上尝试使用提供的字段名称和/或属性类型为参数 fieldType 查找属性反射对象。
     * 搜索所有超类直到 <code>Object</code>。
     * </span>
     *
     * @param clazz     <span class="en-US">Target class instance</span>
     *                  <span class="zh-CN">目标类实例</span>
     * @param name      <span class="en-US">the name of the field</span>
     *                  <span class="zh-CN">字段名称</span>
     * @param fieldType <span class="en-US">the type of the field (maybe <code>null</code> if name is specified)</span>
     *                  <span class="zh-CN">字段的类型（如果指定了名称，则可能是 <code>null</code>）</span>
     * @return <span class="en-US">the corresponding Field object, or <code>null</code> if not found</span>
     * <span class="zh-CN">相应的 Field 对象，如果未找到则为 <code>null</code></span>
     */
    public static Field findField(final Class<?> clazz, final String name, final Class<?> fieldType) {
        if (clazz == null) {
            throw new IllegalArgumentException("Class must not be null");
        }
        if (name == null) {
            throw new IllegalArgumentException("Name of the field must be specified");
        }
        Class<?> searchType = clazz;
        while (!Object.class.equals(searchType) && searchType != null) {
            try {
                Field field = searchType.getDeclaredField(name);
                if ((fieldType == null || fieldType.equals(field.getType()))) {
                    return field;
                }
            } catch (NoSuchFieldException ignored) {
            }
            searchType = searchType.getSuperclass();
        }
        return null;
    }

    /**
     * <h3 class="en-US">Find method instance</h3>
     * <span class="en-US">
     * Attempt to find a method instance on the supplied argument clazz
     * with the supplied <code>name</code>.
     * Searches all superclasses up to <code>Object</code>.
     * </span>
     * <h3 class="zh-CN">查找方法实例</h3>
     * <span class="zh-CN">
     * 尝试使用提供的方法名称在提供的参数 clazz 上查找方法的反射实例对象。
     * 搜索所有超类直到 <code>Object</code>。
     * </span>
     *
     * @param clazz <span class="en-US">Target class instance</span>
     *              <span class="zh-CN">目标类实例</span>
     * @param name  <span class="en-US">the name of the method</span>
     *              <span class="zh-CN">方法名称</span>
     * @return <span class="en-US">the Method object, or <code>null</code> if none found</span>
     * <span class="zh-CN">Method 对象，如果没有找到则为 <code>null</code></span>
     */
    public static Method findMethod(final Class<?> clazz, final String name) {
        return findMethod(clazz, name, new Class[0]);
    }

    /**
     * <h3 class="en-US">Find method instance</h3>
     * <span class="en-US">
     * Attempt to find a method instance on the supplied argument clazz
     * with the supplied <code>name</code> and parameter types.
     * Searches all superclasses up to <code>Object</code>.
     * </span>
     * <h3 class="zh-CN">查找方法实例</h3>
     * <span class="zh-CN">
     * 尝试使用提供的方法名称和参数类型数组在提供的参数 clazz 上查找方法的反射实例对象。
     * 搜索所有超类直到 <code>Object</code>。
     * </span>
     *
     * @param clazz      <span class="en-US">Target class instance</span>
     *                   <span class="zh-CN">目标类实例</span>
     * @param name       <span class="en-US">the name of the method</span>
     *                   <span class="zh-CN">方法名称</span>
     * @param paramTypes <span class="en-US">the parameter types of the method (maybe <code>null</code> to indicate any signature)</span>
     *                   <span class="zh-CN">方法的参数类型（可能是 <code>null</code> 来指示任何签名）</span>
     * @return <span class="en-US">the Method object, or <code>null</code> if none found</span>
     * <span class="zh-CN">Method 对象，如果没有找到则为 <code>null</code></span>
     */
    public static Method findMethod(final Class<?> clazz, final String name, final Class<?>[] paramTypes) {
        if (clazz == null) {
            throw new IllegalArgumentException("Class must not be null");
        }
        if (name == null) {
            throw new IllegalArgumentException("Method name must not be null");
        }
        Class<?> searchType = clazz;
        Class<?>[] paramClasses = ((paramTypes == null) ? new Class[0] : paramTypes);
        while (!Object.class.equals(searchType) && searchType != null) {
            try {
                return searchType.isInterface()
                        ? searchType.getMethod(name, paramClasses)
                        : searchType.getDeclaredMethod(name, paramClasses);
            } catch (NoSuchMethodException ignored) {
            }
            searchType = searchType.getSuperclass();
        }
        return null;
    }

    /**
     * <h3 class="en-US">Find getter method of given field name</h3>
     * <h3 class="zh-CN">查找给定属性的Getter方法实例</h3>
     *
     * @param fieldName   <span class="en-US">Field name</span>
     *                    <span class="zh-CN">属性名</span>
     * @param targetClass <span class="en-US">Target class instance</span>
     *                    <span class="zh-CN">目标类实例</span>
     * @return <span class="en-US">the Method object, or <code>null</code> if none found</span>
     * <span class="zh-CN">Method 对象，如果没有找到则为 <code>null</code></span>
     */
    public static Method getterMethod(final String fieldName, final Class<?> targetClass) {
        return findMethod(fieldName, targetClass, MethodType.Getter);
    }

    /**
     * <h3 class="en-US">Find setter method of given field name</h3>
     * <h3 class="zh-CN">查找给定属性的Setter方法实例</h3>
     *
     * @param fieldName   <span class="en-US">Field name</span>
     *                    <span class="zh-CN">属性名</span>
     * @param targetClass <span class="en-US">Target class instance</span>
     *                    <span class="zh-CN">目标类实例</span>
     * @return <span class="en-US">the Method object, or <code>null</code> if none found</span>
     * <span class="zh-CN">Method 对象，如果没有找到则为 <code>null</code></span>
     */
    public static Method setterMethod(final String fieldName, final Class<?> targetClass) {
        return findMethod(fieldName, targetClass, MethodType.Setter);
    }

    /**
     * <h3 class="en-US">Parse enumeration value string to enumeration instance</h3>
     * <h3 class="zh-CN">将枚举值字符串解析为枚举实例</h3>
     *
     * @param <T>       <span class="en-US">enumeration type class</span>
     *                  <span class="zh-CN">枚举类</span>
     * @param enumClass <span class="en-US">enumeration type class</span>
     *                  <span class="zh-CN">枚举类</span>
     * @param enumValue <span class="en-US">enumeration value string</span>
     *                  <span class="zh-CN">枚举值字符串</span>
     * @return <span class="en-US">Parsed enumeration instance, or <code>null</code> if none found</span>
     * <span class="zh-CN">解析后的枚举实例，如果没有找到则为 <code>null</code></span>
     */
    public static <T> T parseEnum(final Class<T> enumClass, final String enumValue) {
        return Optional.ofNullable(findMethod(enumClass, "valueOf", new Class[]{String.class}))
                .map(method -> {
                    try {
                        return enumClass.cast(invokeMethod(method, null, new Object[]{enumValue}));
                    } catch (Exception ignored) {
                        return null;
                    }
                })
                .orElse(null);
    }

    /**
     * <h3 class="en-US">
     * Set the field represented by the supplied argument field on
     * the specified argument target to the specified argument value.
     * </h3>
     * <span class="en-US">
     * In accordance with <code>Field#set(Object, Object)</code> semantics, the new value is
     * automatically unwrapped if the underlying field has a primitive type.
     * Thrown exceptions are handled via a call to <code>ReflectionUtils#handleReflectionException(Exception)</code>.
     * </span>
     * <h3 class="zh-CN">将指定参数 target 上提供的参数 field 表示的字段设置为参数 value。</h3>
     * <span class="zh-CN">
     * 根据 <code>Field#set(Object, Object)</code> 语义，如果基础字段具有原始类型，则新值会自动解包。
     * 抛出的异常通过调用 <code>ReflectionUtils#handleReflectionException(Exception)</code> 进行处理。
     * </span>
     *
     * @param field  <span class="en-US">the field to set</span>
     *               <span class="zh-CN">要设置的字段</span>
     * @param target <span class="en-US">the target object on which to set the field</span>
     *               <span class="zh-CN">要设置字段的目标对象</span>
     * @param value  <span class="en-US">the value to set; may be <code>null</code></span>
     *               <span class="zh-CN">要设置的值；可能为<code>null</code></span>
     * @see ReflectionUtils#handleReflectionException(Exception)
     */
    public static void setField(final Field field, final Object target, final Object value) {
        try {
            makeAccessible(field);
            field.set(target, value);
        } catch (IllegalAccessException ex) {
            handleReflectionException(ex);
            throw new IllegalStateException(
                    "Unexpected reflection exception - " + ex.getClass().getName() + ": " + ex.getMessage());
        }
    }

    /**
     * <h3 class="en-US">Get the field represented by the supplied argument fieldName on the specified argument target.</h3>
     * <span class="en-US">
     * In accordance with <code>Field#get(Object)</code> semantics, the returned value is
     * automatically wrapped if the underlying field has a primitive type.
     * Thrown exceptions are handled via a call to <code>ReflectionUtils#handleReflectionException(Exception)</code>.
     * </span>
     * <h3 class="zh-CN">获取指定参数 target 上提供的参数 fieldName 表示的字段。</h3>
     * <span class="zh-CN">
     * 根据 <code>Field#get(Object)</code> 语义，如果底层字段具有原始类型，则返回的值会自动包装。
     * 抛出的异常通过调用 <code>ReflectionUtils#handleReflectionException(Exception)</code> 进行处理。
     * </span>
     *
     * @param fieldName <span class="en-US">the name of field to get</span>
     *                  <span class="zh-CN">要获取的字段名称</span>
     * @param target    <span class="en-US">the target object on which to get the field</span>
     *                  <span class="zh-CN">要获取字段的目标对象</span>
     * @return <span class="en-US">the field's current value</span>
     * <span class="zh-CN">该字段的当前值</span>
     * @see ReflectionUtils#handleReflectionException(Exception)
     */
    public static Object getFieldValue(final String fieldName, final Object target) {
        if (fieldName == null || target == null) {
            return null;
        }
        try {
            Method getMethod = getterMethod(fieldName, target.getClass());
            if (getMethod != null) {
                return getMethod.invoke(target);
            } else {
                Field field = getFieldIfAvailable(target.getClass(), fieldName);
                return ReflectionUtils.getFieldValue(field, target);
            }
        } catch (Exception ex) {
            handleReflectionException(ex);
            throw new IllegalStateException(
                    "Unexpected reflection exception - " + ex.getClass().getName() + ": " + ex.getMessage());
        }
    }

    /**
     * <h3 class="en-US">Get the field represented by the supplied argument field on the specified argument target.</h3>
     * <span class="en-US">
     * In accordance with <code>Field#get(Object)</code> semantics, the returned value is
     * automatically wrapped if the underlying field has a primitive type.
     * Thrown exceptions are handled via a call to <code>ReflectionUtils#handleReflectionException(Exception)</code>.
     * </span>
     * <h3 class="zh-CN">获取指定参数 target 上提供的参数 field 表示的字段。</h3>
     * <span class="zh-CN">
     * 根据 <code>Field#get(Object)</code> 语义，如果底层字段具有原始类型，则返回的值会自动包装。
     * 抛出的异常通过调用 <code>ReflectionUtils#handleReflectionException(Exception)</code> 进行处理。
     * </span>
     *
     * @param field  <span class="en-US">the field to get</span>
     *               <span class="zh-CN">要获取的字段</span>
     * @param target <span class="en-US">the target object on which to get the field</span>
     *               <span class="zh-CN">要获取字段的目标对象</span>
     * @return <span class="en-US">the field's current value</span>
     * <span class="zh-CN">该字段的当前值</span>
     * @see ReflectionUtils#handleReflectionException(Exception)
     */
    public static Object getFieldValue(final Field field, final Object target) {
        if (field == null || target == null) {
            return null;
        }
        try {
            makeAccessible(field);
            return field.get(target);
        } catch (IllegalAccessException ex) {
            handleReflectionException(ex);
            throw new IllegalStateException(
                    "Unexpected reflection exception - " + ex.getClass().getName() + ": " + ex.getMessage());
        }
    }

    /**
     * <h3 class="en-US">Execute method object.</h3>
     * <h3 class="zh-CN">执行方法对象。</h3>
     *
     * @param methodName <span class="en-US">the method name</span>
     *                   <span class="zh-CN">方法名称</span>
     * @param target     <span class="en-US">the target object on which to execute the method</span>
     *                   <span class="zh-CN">执行方法的目标对象</span>
     * @return <span class="en-US">the execute result value</span>
     * <span class="zh-CN">执行结果值</span>
     * @throws IllegalArgumentException <span class="en-US">If method not found</span>
     *                                  <span class="zh-CN">如果方法未找到</span>
     */
    public static Object invokeMethod(final String methodName, final Object target)
            throws IllegalArgumentException {
        return invokeMethod(methodName, target, new Class[]{});
    }

    /**
     * <h3 class="en-US">Invoke the specified method against the supplied target object with the supplied arguments.</h3>
     * <span class="en-US">
     * The target object can be <code>null</code> when invoking a static method.
     * Thrown exceptions are handled via a call to <code>ReflectionUtils#handleReflectionException(Exception)</code>.
     * </span>
     * <h3 class="zh-CN">使用提供的参数针对提供的目标对象调用指定的方法</h3>
     * <span class="zh-CN">
     * 调用静态方法时，目标对象可以为 <code>null</code>。
     * 抛出的异常是通过调用 <code>ReflectionUtils#handleReflectionException(Exception)</code> 来处理的。
     * </span>
     *
     * @param methodName   <span class="en-US">the method name</span>
     *                     <span class="zh-CN">方法名称</span>
     * @param target       <span class="en-US">the target object on which to execute the method</span>
     *                     <span class="zh-CN">执行方法的目标对象</span>
     * @param paramClasses <span class="en-US">the parameter class array of the method</span>
     *                     <span class="zh-CN">方法的参数类数组</span>
     * @param args         <span class="en-US">the parameter object array of the method</span>
     *                     <span class="zh-CN">方法的参数对象数组</span>
     * @return <span class="en-US">the execute result value</span>
     * <span class="zh-CN">执行结果值</span>
     * @throws IllegalArgumentException <span class="en-US">If method not found</span>
     *                                  <span class="zh-CN">如果方法未找到</span>
     * @see ReflectionUtils#invokeMethod(java.lang.reflect.Method, Object, Object[])
     * @see ReflectionUtils#handleReflectionException(Exception)
     */
    public static Object invokeMethod(final String methodName, final Object target,
                                      final Class<?>[] paramClasses, final Object... args)
            throws IllegalArgumentException {
        Class<?>[] parameterTypes = CollectionUtils.isEmpty(paramClasses) ? new Class[0] : paramClasses;
        Object[] parameterValues = CollectionUtils.isEmpty(args) ? new Object[0] : args;
        if (parameterValues.length != parameterTypes.length) {
            throw new IllegalArgumentException("Arguments not matched! ");
        }
        Method method = findMethod(target.getClass(), methodName, parameterTypes);
        if (method == null) {
            throw new IllegalArgumentException("Method named : " + methodName + " does not exists");
        }
        ReflectionUtils.makeAccessible(method);
        return invokeMethod(method, target, parameterValues);
    }

    /**
     * <h3 class="en-US">Invoke the specified method against the supplied target object with no arguments.</h3>
     * <span class="en-US">
     * The target object can be <code>null</code> when invoking a static method.
     * Thrown exceptions are handled via a call to <code>ReflectionUtils#handleReflectionException(Exception)</code>.
     * </span>
     * <h3 class="zh-CN">对提供的目标对象调用指定的方法 method（不带任何参数）。</h3>
     * <span class="zh-CN">
     * 调用静态方法时，目标对象可以为 <code>null</code>。
     * 抛出的异常是通过调用 <code>ReflectionUtils#handleReflectionException(Exception)</code> 来处理的。
     * </span>
     *
     * @param method <span class="en-US">the method to invoke</span>
     *               <span class="zh-CN">调用的方法</span>
     * @param target <span class="en-US">the target object on which to execute the method</span>
     *               <span class="zh-CN">执行方法的目标对象</span>
     * @return <span class="en-US">the execute result value</span>
     * <span class="zh-CN">执行结果值</span>
     * @see ReflectionUtils#invokeMethod(java.lang.reflect.Method, Object, Object[])
     * @see ReflectionUtils#handleReflectionException(Exception)
     */
    public static Object invokeMethod(final Method method, final Object target) {
        return invokeMethod(method, target, null);
    }

    /**
     * <h3 class="en-US">Invoke the specified method against the supplied target object with the supplied arguments.</h3>
     * <span class="en-US">
     * The target object can be <code>null</code> when invoking a static method.
     * Thrown exceptions are handled via a call to <code>ReflectionUtils#handleReflectionException(Exception)</code>.
     * </span>
     * <h3 class="zh-CN">使用提供的参数针对提供的目标对象调用指定的方法</h3>
     * <span class="zh-CN">
     * 调用静态方法时，目标对象可以为 <code>null</code>。
     * 抛出的异常是通过调用 <code>ReflectionUtils#handleReflectionException(Exception)</code> 来处理的。
     * </span>
     *
     * @param method <span class="en-US">the method to invoke</span>
     *               <span class="zh-CN">调用的方法</span>
     * @param target <span class="en-US">the target object on which to execute the method</span>
     *               <span class="zh-CN">执行方法的目标对象</span>
     * @param args   <span class="en-US">the invocation arguments (maybe <code>null</code>)</span>
     *               <span class="zh-CN">调用参数（可能<code>null</code>）</span>
     * @return <span class="en-US">the execute result value</span>
     * <span class="zh-CN">执行结果值</span>
     * @see ReflectionUtils#invokeMethod(java.lang.reflect.Method, Object, Object[])
     * @see ReflectionUtils#handleReflectionException(Exception)
     */
    public static Object invokeMethod(final Method method, final Object target, final Object[] args) {
        try {
            return method.invoke(target, args);
        } catch (Exception ex) {
            handleReflectionException(ex);
        }
        throw new IllegalStateException("Should never get here");
    }

    /**
     * <h3 class="en-US">Handle the given reflection exception.</h3>
     * <span class="en-US">
     * Should only be called if no checked exception is expected to be thrown by the target method.
     * Throws the underlying RuntimeException or Error in case of an
     * InvocationTargetException with such a root cause.
     * Throw an IllegalStateException with an appropriate message else.
     * </span>
     * <h3 class="zh-CN">处理给定的反射异常。</h3>
     * <span class="zh-CN">
     * 仅当目标方法预计不会引发已检查异常时才应调用。
     * 如果出现具有此类根本原因的 InspirationTargetException，则抛出基础 RuntimeException 或 Error。
     * 抛出 IllegalStateException 并附加适当的消息。
     * </span>
     *
     * @param ex <span class="en-US">the reflection exception to handle</span>
     *           <span class="zh-CN">要处理的反射异常</span>
     */
    public static void handleReflectionException(final Exception ex) {
        if (ex instanceof NoSuchMethodException) {
            throw new IllegalStateException("Method not found: " + ex.getMessage());
        }
        if (ex instanceof IllegalAccessException) {
            throw new IllegalStateException("Could not access method: " + ex.getMessage());
        }
        if (ex instanceof InvocationTargetException) {
            handleInvocationTargetException((InvocationTargetException) ex);
        }
        if (ex instanceof RuntimeException) {
            throw (RuntimeException) ex;
        }
        handleUnexpectedException(ex);
    }

    /**
     * <h3 class="en-US">Handle the given invocation exception.</h3>
     * <span class="en-US">
     * Should only be called if no checked exception is expected to be thrown by the target method.
     * Throws the underlying RuntimeException or Error in case of such a root cause.
     * Throws an IllegalStateException else.
     * </span>
     * <h3 class="zh-CN">处理给定的调用异常。</h3>
     * <span class="zh-CN">
     * 仅当目标方法预计不会引发已检查异常时才应调用。
     * 如果出现此类根本原因，则抛出底层 RuntimeException 或 Error。
     * 否则抛出 IllegalStateException。
     * </span>
     *
     * @param ex <span class="en-US">the invocation exception to handle</span>
     *           <span class="zh-CN">要处理的调用异常</span>
     */
    public static void handleInvocationTargetException(final InvocationTargetException ex) {
        rethrowRuntimeException(ex.getTargetException());
    }

    /**
     * <h3 class="en-US">Rethrow the given argument ex</h3>
     * <span class="en-US">
     * which is presumably the <em>target exception</em> of an <code>InvocationTargetException</code>.
     * Should only be called if no checked exception is expected to be thrown by the target method.
     * Rethrows the underlying exception cast to an <code>RuntimeException</code> or <code>Error</code> if appropriate;
     * otherwise, throws an <code>IllegalStateException</code>.
     * </span>
     * <h3 class="zh-CN">重新抛出给定的参数 ex</h3>
     * <span class="zh-CN">
     * 这可能是 <code>InvocationTargetException</code> 的<em>目标异常</em>。
     * 仅当目标方法预计不会引发已检查异常时才应调用。
     * 如果适用，重新抛出底层异常转换为 <code>RuntimeException</code> 或 <code>Error</code>；
     * 否则，抛出一个<code>IllegalStateException</code>。
     * </span>
     *
     * @param ex <span class="en-US">the exception to rethrow</span>
     *           <span class="zh-CN">要重新抛出的异常</span>
     * @throws RuntimeException <span class="en-US">the rethrown exception (in case of a checked exception)</span>
     *                          <span class="zh-CN">重新抛出的异常（在检查异常的情况下）</span>
     */
    public static void rethrowRuntimeException(final Throwable ex) {
        if (ex instanceof RuntimeException) {
            throw (RuntimeException) ex;
        }
        if (ex instanceof Error) {
            throw (Error) ex;
        }
        handleUnexpectedException(ex);
    }

    /**
     * <h3 class="en-US">Rethrow the given argument ex</h3>
     * <span class="en-US">
     * which is presumably the <em>target exception</em> of an <code>InvocationTargetException</code>.
     * Should only be called if no checked exception is expected to be thrown by the target method.
     * Rethrows the underlying exception cast to an <code>Exception</code> or <code>Error</code> if appropriate;
     * otherwise, throws an <code>IllegalStateException</code>.
     * </span>
     * <h3 class="zh-CN">重新抛出给定的参数 ex</h3>
     * <span class="zh-CN">
     * 这可能是 <code>InvocationTargetException</code> 的<em>目标异常</em>。
     * 仅当目标方法预计不会引发已检查异常时才应调用。
     * 如果适用，重新抛出底层异常转换为 <code>Exception</code> 或 <code>Error</code>；
     * 否则，抛出一个<code>IllegalStateException</code>。
     * </span>
     *
     * @param ex <span class="en-US">the exception to rethrow</span>
     *           <span class="zh-CN">要重新抛出的异常</span>
     * @throws Exception <span class="en-US">the rethrown exception (in case of a checked exception)</span>
     *                   <span class="zh-CN">重新抛出的异常（在检查异常的情况下）</span>
     */
    public static void rethrowException(final Throwable ex) throws Exception {
        if (ex instanceof Exception) {
            throw (Exception) ex;
        }
        if (ex instanceof Error) {
            throw (Error) ex;
        }
        handleUnexpectedException(ex);
    }

    /**
     * <h3 class="en-US">
     * Determine whether the given method explicitly declares the given exception
     * or one of its superclasses, which means that an exception to that type
     * can be propagated as-is within a reflective invocation.
     * </h3>
     * <h3 class="zh-CN">确定给定方法是否显式声明给定异常或其超类之一，这意味着该类型的异常可以在反射调用中按原样传播。</h3>
     *
     * @param method        <span class="en-US">the declaring method</span>
     *                      <span class="zh-CN">声明方法</span>
     * @param exceptionType <span class="en-US">the exception to throw</span>
     *                      <span class="zh-CN">要抛出的异常</span>
     * @return <span class="en-US"><code>true</code> if the exception can be thrown as-is; <code>false</code> if it needs to be wrapped</span>
     * <span class="zh-CN">如果异常可以按原样抛出则返回<code>true</code>；如果需要包装则返回<code>false</code></span>
     */
    public static boolean declaresException(final Method method, final Class<?> exceptionType) {
        if (method == null) {
            throw new IllegalArgumentException("Method must not be null");
        }
        Class<?>[] declaredExceptions = method.getExceptionTypes();
        for (Class<?> declaredException : declaredExceptions) {
            if (declaredException.isAssignableFrom(exceptionType)) {
                return Boolean.TRUE;
            }
        }
        return Boolean.FALSE;
    }

    /**
     * <h3 class="en-US">Determine whether the given field/method is a "public" member.</h3>
     * <h3 class="zh-CN">确定给定的字段/方法是否是“公共”成员。</h3>
     *
     * @param member <span class="en-US">the field/method to check</span>
     *               <span class="zh-CN">要检查的字段/方法</span>
     * @return <span class="en-US">is a "public" member.</span>
     * <span class="zh-CN">是一个“公共”成员。</span>
     */
    public static boolean publicMember(final Member member) {
        return Optional.ofNullable(member)
                .map(checkMember -> Modifier.isPublic(checkMember.getModifiers()))
                .orElse(Boolean.FALSE);
    }

    /**
     * <h3 class="en-US">Determine whether the given field/method is a "protected" member.</h3>
     * <h3 class="zh-CN">确定给定的字段/方法是否是“保护”成员。</h3>
     *
     * @param member <span class="en-US">the field/method to check</span>
     *               <span class="zh-CN">要检查的字段/方法</span>
     * @return <span class="en-US">is a "protected" member.</span>
     * <span class="zh-CN">是一个“保护”成员。</span>
     */
    public static boolean protectedMember(final Member member) {
        return Optional.ofNullable(member)
                .map(checkMember -> Modifier.isProtected(checkMember.getModifiers()))
                .orElse(Boolean.FALSE);
    }

    /**
     * <h3 class="en-US">Determine whether the given field/method is a "private" member.</h3>
     * <h3 class="zh-CN">确定给定的字段/方法是否是“私有”成员。</h3>
     *
     * @param member <span class="en-US">the field/method to check</span>
     *               <span class="zh-CN">要检查的字段/方法</span>
     * @return <span class="en-US">is a "private" member.</span>
     * <span class="zh-CN">是一个“私有”成员。</span>
     */
    public static boolean privateMember(final Member member) {
        return Optional.ofNullable(member)
                .map(checkMember -> Modifier.isPrivate(checkMember.getModifiers()))
                .orElse(Boolean.FALSE);
    }

    /**
     * <h3 class="en-US">Determine whether the given field/method is a "static" member.</h3>
     * <h3 class="zh-CN">确定给定的字段/方法是否是“静态”成员。</h3>
     *
     * @param member <span class="en-US">the field/method to check</span>
     *               <span class="zh-CN">要检查的字段/方法</span>
     * @return <span class="en-US">is a "static" member.</span>
     * <span class="zh-CN">是一个“静态”成员。</span>
     */
    public static boolean staticMember(final Member member) {
        return Optional.ofNullable(member)
                .map(checkMember -> Modifier.isStatic(checkMember.getModifiers()))
                .orElse(Boolean.FALSE);
    }

    /**
     * <h3 class="en-US">Determine whether the given field/method is a "final" member.</h3>
     * <h3 class="zh-CN">确定给定的字段/方法是否是“最终”成员。</h3>
     *
     * @param member <span class="en-US">the field/method to check</span>
     *               <span class="zh-CN">要检查的字段/方法</span>
     * @return <span class="en-US">is a "final" member.</span>
     * <span class="zh-CN">是一个“最终”成员。</span>
     */
    public static boolean finalMember(final Member member) {
        return Optional.ofNullable(member)
                .map(checkMember -> Modifier.isFinal(checkMember.getModifiers()))
                .orElse(Boolean.FALSE);
    }

    /**
     * <h3 class="en-US">Determine whether the given field/method is a "public static final" member.</h3>
     * <h3 class="zh-CN">确定给定的字段/方法是否是“公开静态最终”成员。</h3>
     *
     * @param member <span class="en-US">the field/method to check</span>
     *               <span class="zh-CN">要检查的字段/方法</span>
     * @return <span class="en-US">is a "public static final" member.</span>
     * <span class="zh-CN">是一个“公开静态最终”成员。</span>
     */
    public static boolean isPublicStaticFinal(final Member member) {
        return publicMember(member) && staticMember(member) && finalMember(member);
    }

    /**
     * <h3 class="en-US">Make the given field accessible, explicitly setting it accessible if necessary.</h3>
     * <span class="en-US">
     * The <code>setAccessible(true)</code> method is only called when actually necessary,
     * to avoid unnecessary conflicts with a JVM SecurityManager (if active).
     * </span>
     * <h3 class="zh-CN">使给定字段可访问，必要时明确将其设置为可访问。</h3>
     * <span class="zh-CN">
     * <code>setAccessible(true)</code> 方法仅在实际需要时调用，以避免与 JVM SecurityManager（如果处于活动状态）发生不必要的冲突。
     * </span>
     *
     * @param field <span class="en-US">the field to make accessible</span>
     *              <span class="zh-CN">使可访问的字段/span>
     * @see java.lang.reflect.Field#setAccessible
     */
    public static void makeAccessible(final Field field) {
        if (privateMember(field) || protectedMember(field) ||
                !Modifier.isPublic(field.getDeclaringClass().getModifiers())) {
            field.setAccessible(Boolean.TRUE);
        }
    }

    /**
     * <h3 class="en-US">Make the given method accessible, explicitly setting it accessible if necessary.</h3>
     * <span class="en-US">
     * The <code>setAccessible(true)</code> method is only called when actually necessary,
     * to avoid unnecessary conflicts with a JVM SecurityManager (if active).
     * </span>
     * <h3 class="zh-CN">使给定方法可访问，必要时明确将其设置为可访问。</h3>
     * <span class="zh-CN">
     * <code>setAccessible(true)</code> 方法仅在实际需要时调用，以避免与 JVM SecurityManager（如果处于活动状态）发生不必要的冲突。
     * </span>
     *
     * @param method <span class="en-US">the method to make accessible</span>
     *               <span class="zh-CN">使可访问的方法</span>
     * @see java.lang.reflect.Method#setAccessible
     */
    public static void makeAccessible(final Method method) {
        if (privateMember(method) || protectedMember(method) ||
                !Modifier.isPublic(method.getDeclaringClass().getModifiers())) {
            method.setAccessible(true);
        }
    }

    /**
     * <h3 class="en-US">Make the given constructor accessible, explicitly setting it accessible if necessary.</h3>
     * <span class="en-US">
     * The <code>setAccessible(true)</code> method is only called when actually necessary,
     * to avoid unnecessary conflicts with a JVM SecurityManager (if active).
     * </span>
     * <h3 class="zh-CN">使给定构造方法可访问，必要时明确将其设置为可访问。</h3>
     * <span class="zh-CN">
     * <code>setAccessible(true)</code> 方法仅在实际需要时调用，以避免与 JVM SecurityManager（如果处于活动状态）发生不必要的冲突。
     * </span>
     *
     * @param ctor <span class="en-US">the constructor to make accessible</span>
     *             <span class="zh-CN">使可访问的构造方法</span>
     * @see java.lang.reflect.Constructor#setAccessible
     */
    public static void makeAccessible(final Constructor<?> ctor) {
        if (!Modifier.isPublic(ctor.getModifiers()) ||
                !Modifier.isPublic(ctor.getDeclaringClass().getModifiers())) {
            ctor.setAccessible(true);
        }
    }

    /**
     * <h3 class="en-US">Gets all non-static declared fields from given class.</h3>
     * <h3 class="zh-CN">获取给定类的所有声明的非静态属性。</h3>
     *
     * @param clazz <span class="en-US">given class</span>
     *              <span class="zh-CN">给定的类</span>
     * @return <span class="en-US">all non-static declared fields list, or empty list if given class is <code>null</code></span>
     * <span class="zh-CN">所有声明的非静态属性列表，如果给定的类为 <code>null</code>则返回空列表</span>
     */
    public static List<Field> getAllDeclaredFields(Class<?> clazz) {
        return getAllDeclaredFields(clazz, Boolean.FALSE);
    }

    /**
     * <h3 class="en-US">Gets all non-static declared fields from given class.</h3>
     * <h3 class="zh-CN">获取给定类的所有声明的非静态属性。</h3>
     *
     * @param clazz        <span class="en-US">given class</span>
     *                     <span class="zh-CN">给定的类</span>
     * @param memberFilter <span class="en-US">Field filter (maybe <code>null</code> for process callback at all fields)</span>
     *                     <span class="zh-CN">属性过滤器（当为<code>null</code>时为所有的属性执行回调）</span>
     * @return <span class="en-US">all non-static declared fields list, or empty list if given class is <code>null</code></span>
     * <span class="zh-CN">所有声明的非静态属性列表，如果给定的类为 <code>null</code>则返回空列表</span>
     */
    public static List<Field> getAllDeclaredFields(Class<?> clazz, final MemberFilter memberFilter) {
        return getAllDeclaredFields(clazz, Boolean.FALSE, memberFilter);
    }

    /**
     * <h3 class="en-US">Gets all non-static declared fields from given class.</h3>
     * <h3 class="zh-CN">获取给定类的所有声明的非静态属性。</h3>
     *
     * @param clazz            <span class="en-US">given class</span>
     *                         <span class="zh-CN">给定的类</span>
     * @param parseParent      <span class="en-US">Retrieve fields from parent class</span>
     *                         <span class="zh-CN">获取父类的非静态属性</span>
     * @param classAnnotations <span class="en-US">
     *                         Parent class annotation arrays, only using for parameter parseParent
     *                         is <code>Boolean.TRUE</code>.
     *                         Parent class will parsed which class was annotation with anyone of annotation arrays
     *                         or annotation arrays is <code>null</code> or empty.
     *                         </span>
     *                         <span class="zh-CN">
     *                         父类的注解数组，仅用于参数parseParent为<code>Boolean.TRUE</code>时。
     *                         父类必须使用注解数组中的任一注解进行标注，或注解数组为<code>null</code>或空数组时，才会解析
     *                         </span>
     * @return <span class="en-US">all non-static declared fields list, or empty list if given class is <code>null</code></span>
     * <span class="zh-CN">所有声明的非静态属性列表，如果给定的类为 <code>null</code>则返回空列表</span>
     */
    @SafeVarargs
    public static List<Field> getAllDeclaredFields(Class<?> clazz, final boolean parseParent,
                                                   final Class<? extends Annotation>... classAnnotations) {
        return getAllDeclaredFields(clazz, parseParent, new AnnotationClassFilter(classAnnotations));
    }

    /**
     * <h3 class="en-US">Gets all non-static declared fields from given class.</h3>
     * <h3 class="zh-CN">获取给定类的所有声明的非静态属性。</h3>
     *
     * @param clazz       <span class="en-US">given class</span>
     *                    <span class="zh-CN">给定的类</span>
     * @param parseParent <span class="en-US">Retrieve fields from parent class</span>
     *                    <span class="zh-CN">获取父类的非静态属性</span>
     * @param classFilter <span class="en-US">Parent class filter (maybe <code>null</code> for process all parent class)</span>
     *                    <span class="zh-CN">父类过滤器（当为<code>null</code>时处理所有父类）</span>
     * @return <span class="en-US">all non-static declared fields list, or empty list if given class is <code>null</code> or an error occurs</span>
     * <span class="zh-CN">所有声明的非静态属性列表，如果给定的类为 <code>null</code>或出现异常则返回空列表</span>
     */
    public static List<Field> getAllDeclaredFields(Class<?> clazz, final boolean parseParent,
                                                   final ClassFilter classFilter) {
        return getAllDeclaredFields(clazz, parseParent, classFilter, NON_STATIC_FINAL_MEMBERS);
    }

    /**
     * <h3 class="en-US">Gets all non-static declared fields from given class.</h3>
     * <h3 class="zh-CN">获取给定类的所有声明的非静态属性。</h3>
     *
     * @param clazz        <span class="en-US">given class</span>
     *                     <span class="zh-CN">给定的类</span>
     * @param parseParent  <span class="en-US">Retrieve fields from parent class</span>
     *                     <span class="zh-CN">获取父类的非静态属性</span>
     * @param memberFilter <span class="en-US">Field filter (maybe <code>null</code> for process callback at all fields)</span>
     *                     <span class="zh-CN">属性过滤器（当为<code>null</code>时为所有的属性执行回调）</span>
     * @return <span class="en-US">all non-static declared fields list, or empty list if given class is <code>null</code></span>
     * <span class="zh-CN">所有声明的非静态属性列表，如果给定的类为 <code>null</code>则返回空列表</span>
     */
    public static List<Field> getAllDeclaredFields(Class<?> clazz, final boolean parseParent,
                                                   final MemberFilter memberFilter) {
        return getAllDeclaredFields(clazz, parseParent, null, memberFilter);
    }

    /**
     * <h3 class="en-US">Gets all non-static declared fields from given class.</h3>
     * <h3 class="zh-CN">获取给定类的所有声明的非静态属性。</h3>
     *
     * @param clazz        <span class="en-US">given class</span>
     *                     <span class="zh-CN">给定的类</span>
     * @param parseParent  <span class="en-US">Retrieve fields from parent class</span>
     *                     <span class="zh-CN">获取父类的非静态属性</span>
     * @param classFilter  <span class="en-US">Parent class filter (maybe <code>null</code> for process all parent class)</span>
     *                     <span class="zh-CN">父类过滤器（当为<code>null</code>时处理所有父类）</span>
     * @param memberFilter <span class="en-US">Field filter (maybe <code>null</code> for process callback at all fields)</span>
     *                     <span class="zh-CN">属性过滤器（当为<code>null</code>时为所有的属性执行回调）</span>
     * @return <span class="en-US">all non-static declared fields list, or empty list if given class is <code>null</code> or an error occurs</span>
     * <span class="zh-CN">所有声明的非静态属性列表，如果给定的类为 <code>null</code>或出现异常则返回空列表</span>
     */
    public static List<Field> getAllDeclaredFields(Class<?> clazz, final boolean parseParent,
                                                   final ClassFilter classFilter, final MemberFilter memberFilter) {
        try {
            List<Field> fieldList = new ArrayList<>();
            doWithFields(clazz, fieldList::add, parseParent, classFilter, memberFilter);
            return fieldList;
        } catch (IllegalArgumentException | IllegalAccessException e) {
            LOGGER.error("Fields_Retrieve_Reflection_Error");
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Stack_Message_Error", e);
            }
            return Collections.emptyList();
        }
    }

    /**
     * <h3 class="en-US">Get all declared methods on the given class and all superclasses. Leaf class methods are included first.</h3>
     * <h3 class="zh-CN">获取给定类和所有超类的所有声明方法。首先包含叶类方法。</h3>
     *
     * @param clazz <span class="en-US">given class</span>
     *              <span class="zh-CN">给定的类</span>
     * @return <span class="en-US">All declared method list, or empty list if given class is <code>null</code> or an error occurs</span>
     * <span class="zh-CN">所有声明的方法列表，如果给定的类为 <code>null</code>或出现异常则返回空列表</span>
     */
    public static List<Method> getAllDeclaredMethods(Class<?> clazz) {
        return getAllDeclaredMethods(clazz, Boolean.FALSE, null, null);
    }

    /**
     * <h3 class="en-US">Get all declared methods on the given class and all superclasses. Leaf class methods are included first.</h3>
     * <h3 class="zh-CN">获取给定类和所有超类的所有声明方法。首先包含叶类方法。</h3>
     *
     * @param clazz        <span class="en-US">given class</span>
     *                     <span class="zh-CN">给定的类</span>
     * @param memberFilter <span class="en-US">Method filter (maybe <code>null</code> for process callback at all fields)</span>
     *                     <span class="zh-CN">方法过滤器（当为<code>null</code>时为所有的属性执行回调）</span>
     * @return <span class="en-US">All declared method list, or empty list if given class is <code>null</code> or an error occurs</span>
     * <span class="zh-CN">所有声明的方法列表，如果给定的类为 <code>null</code>或出现异常则返回空列表</span>
     */
    public static List<Method> getAllDeclaredMethods(Class<?> clazz, final MemberFilter memberFilter) {
        return getAllDeclaredMethods(clazz, Boolean.FALSE, memberFilter);
    }

    /**
     * <h3 class="en-US">Get all declared methods on the given class and all superclasses. Leaf class methods are included first.</h3>
     * <h3 class="zh-CN">获取给定类和所有超类的所有声明方法。首先包含叶类方法。</h3>
     *
     * @param clazz       <span class="en-US">given class</span>
     *                    <span class="zh-CN">给定的类</span>
     * @param parseParent <span class="en-US">Retrieve fields from parent class</span>
     *                    <span class="zh-CN">获取父类的非静态属性</span>
     * @return <span class="en-US">All declared method list, or empty list if given class is <code>null</code> or an error occurs</span>
     * <span class="zh-CN">所有声明的方法列表，如果给定的类为 <code>null</code>或出现异常则返回空列表</span>
     */
    public static List<Method> getAllDeclaredMethods(Class<?> clazz, final boolean parseParent) {
        return getAllDeclaredMethods(clazz, parseParent, null, null);
    }

    /**
     * <h3 class="en-US">Get all declared methods on the given class and all superclasses. Leaf class methods are included first.</h3>
     * <h3 class="zh-CN">获取给定类和所有超类的所有声明方法。首先包含叶类方法。</h3>
     *
     * @param clazz            <span class="en-US">given class</span>
     *                         <span class="zh-CN">给定的类</span>
     * @param parseParent      <span class="en-US">Retrieve fields from parent class</span>
     *                         <span class="zh-CN">获取父类的非静态属性</span>
     * @param classAnnotations <span class="en-US">
     *                         Parent class annotation arrays, only using for parameter parseParent
     *                         is <code>Boolean.TRUE</code>.
     *                         Parent class will parsed which class was annotation with anyone of annotation arrays
     *                         or annotation arrays is <code>null</code> or empty.
     *                         </span>
     *                         <span class="zh-CN">
     *                         父类的注解数组，仅用于参数parseParent为<code>Boolean.TRUE</code>时。
     *                         父类必须使用注解数组中的任一注解进行标注，或注解数组为<code>null</code>或空数组时，才会解析
     *                         </span>
     * @return <span class="en-US">All declared method list, or empty list if given class is <code>null</code> or an error occurs</span>
     * <span class="zh-CN">所有声明的方法列表，如果给定的类为 <code>null</code>或出现异常则返回空列表</span>
     */
    @SafeVarargs
    public static List<Method> getAllDeclaredMethods(Class<?> clazz, final boolean parseParent,
                                                     final Class<? extends Annotation>... classAnnotations) {
        return getAllDeclaredMethods(clazz, parseParent, new AnnotationClassFilter(classAnnotations), null);
    }

    /**
     * <h3 class="en-US">Get all declared methods on the given class and all superclasses. Leaf class methods are included first.</h3>
     * <h3 class="zh-CN">获取给定类和所有超类的所有声明方法。首先包含叶类方法。</h3>
     *
     * @param clazz        <span class="en-US">given class</span>
     *                     <span class="zh-CN">给定的类</span>
     * @param parseParent  <span class="en-US">Retrieve fields from parent class</span>
     *                     <span class="zh-CN">获取父类的非静态属性</span>
     * @param memberFilter <span class="en-US">Method filter (maybe <code>null</code> for process callback at all fields)</span>
     *                     <span class="zh-CN">方法过滤器（当为<code>null</code>时为所有的属性执行回调）</span>
     * @return <span class="en-US">All declared method list, or empty list if given class is <code>null</code> or an error occurs</span>
     * <span class="zh-CN">所有声明的方法列表，如果给定的类为 <code>null</code>或出现异常则返回空列表</span>
     */
    public static List<Method> getAllDeclaredMethods(Class<?> clazz, final boolean parseParent,
                                                     final MemberFilter memberFilter) {
        return getAllDeclaredMethods(clazz, parseParent, null, memberFilter);
    }

    /**
     * <h3 class="en-US">Get all declared methods on the given class and all superclasses. Leaf class methods are included first.</h3>
     * <h3 class="zh-CN">获取给定类和所有超类的所有声明方法。首先包含叶类方法。</h3>
     *
     * @param clazz        <span class="en-US">given class</span>
     *                     <span class="zh-CN">给定的类</span>
     * @param parseParent  <span class="en-US">Retrieve fields from parent class</span>
     *                     <span class="zh-CN">获取父类的非静态属性</span>
     * @param classFilter  <span class="en-US">Parent class filter (maybe <code>null</code> for process all parent class)</span>
     *                     <span class="zh-CN">父类过滤器（当为<code>null</code>时处理所有父类）</span>
     * @param memberFilter <span class="en-US">Method filter (maybe <code>null</code> for process callback at all fields)</span>
     *                     <span class="zh-CN">方法过滤器（当为<code>null</code>时为所有的属性执行回调）</span>
     * @return <span class="en-US">All declared method list, or empty list if given class is <code>null</code> or an error occurs</span>
     * <span class="zh-CN">所有声明的方法列表，如果给定的类为 <code>null</code>或出现异常则返回空列表</span>
     */
    public static List<Method> getAllDeclaredMethods(Class<?> clazz, final boolean parseParent,
                                                     final ClassFilter classFilter, final MemberFilter memberFilter) {
        try {
            final List<Method> methodList = new ArrayList<>();
            doWithMethods(clazz, methodList::add, parseParent, classFilter, memberFilter);
            return methodList;
        } catch (IllegalArgumentException e) {
            LOGGER.error("Methods_Retrieve_Reflection_Error");
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Stack_Message_Error", e);
            }
            return Collections.emptyList();
        }
    }

    /**
     * <h3 class="en-US">Shallow copy from argument src to dest</h3>
     * <span class="en-US">
     * Given the source object and the destination, which must be the same class
     * or a subclass, copy all fields, including inherited fields.
     * Designed to work on objects with public no-arg constructors.
     * </span>
     * <h3 class="zh-CN">从参数 src 浅复制到 dest</h3>
     * <span class="zh-CN">
     * 给定源对象和目标（必须是同一类或子类），复制所有字段，包括继承的字段。
     * 设计用于处理具有公共无参数构造函数的对象。
     * </span>
     *
     * @param src  <span class="en-US">source object</span>
     *             <span class="zh-CN">源对象</span>
     * @param dest <span class="en-US">target object</span>
     *             <span class="zh-CN">目标对象</span>
     * @throws IllegalArgumentException <span class="en-US">if the arguments are incompatible</span>
     *                                  <span class="zh-CN">如果参数不兼容</span>
     */
    public static void shallowCopyFieldState(final Object src, final Object dest)
            throws IllegalArgumentException, IllegalAccessException {
        if (src == null) {
            throw new IllegalArgumentException("Source for field copy cannot be null");
        }
        if (dest == null) {
            throw new IllegalArgumentException("Destination for field copy cannot be null");
        }
        if (!src.getClass().isAssignableFrom(dest.getClass())) {
            throw new IllegalArgumentException("Destination class [" + dest.getClass().getName() +
                    "] must be same or subclass as source class [" + src.getClass().getName() + "]");
        }
        doWithFields(src.getClass(), field -> {
            makeAccessible(field);
            Object srcValue = field.get(src);
            field.set(dest, srcValue);
        }, Boolean.TRUE, null, NON_STATIC_FINAL_MEMBERS);
    }

    /**
     * <h3 class="en-US">Retrieve the field object named by given argument fieldName on the given class and all superclasses.</h3>
     * <h3 class="zh-CN">检索给定类和所有超类上由给定参数 fieldName 命名的属性对象。</h3>
     *
     * @param clazz     <span class="en-US">given class</span>
     *                  <span class="zh-CN">给定的类</span>
     * @param fieldName <span class="en-US">field name</span>
     *                  <span class="zh-CN">属性名</span>
     * @return <span class="en-US">Retrieve the field object or <code>null</code> if not exists</span>
     * <span class="zh-CN">检索到的属性对象，如果不存在则返回 <code>null</code></span>
     */
    public static Field getFieldIfAvailable(final Class<?> clazz, final String fieldName) {
        if (clazz == null) {
            return null;
        }
        try {
            return clazz.getDeclaredField(fieldName);
        } catch (Exception e) {
            return getFieldIfAvailable(clazz.getSuperclass(), fieldName);
        }
    }

    /**
     * <h3 class="en-US">Set the field values by given argument parameterMap(key is field name, value is field value) to the argument target instance.</h3>
     * <h3 class="zh-CN">通过给定的参数 parameterMap （键是属性名称，值是属性值）将数据设置到参数 target 实例。</h3>
     *
     * @param target       <span class="en-US">Target instance</span>
     *                     <span class="zh-CN">目标实例对象</span>
     * @param parameterMap <span class="en-US">field data map</span>
     *                     <span class="zh-CN">属性数据映射表</span>
     */
    public static void setField(final Object target, final Map<String, ?> parameterMap) {
        if (target == null || parameterMap == null) {
            return;
        }
        parameterMap.forEach((key, value) -> {
            Object fieldValue;
            if (value.getClass().isArray()) {
                if (((Object[]) value).length == 1) {
                    fieldValue = ((Object[]) value)[0];
                } else {
                    fieldValue = value;
                }
            } else {
                fieldValue = value;
            }

            setField(key, target, fieldValue);
        });
    }

    /**
     * <h3 class="en-US">Set the field value by given argument fieldName to the argument target instance.</h3>
     * <h3 class="zh-CN">通过给定的参数 fieldName 找到参数 target 实例中的属性对象，并将属性值设置为参数 value 值。</h3>
     *
     * @param fieldName <span class="en-US">field name</span>
     *                  <span class="zh-CN">属性名</span>
     * @param target    <span class="en-US">the target object on which to set the field</span>
     *                  <span class="zh-CN">要设置字段的目标对象</span>
     * @param value     <span class="en-US">the value to set; may be <code>null</code></span>
     *                  <span class="zh-CN">要设置的值；可能为<code>null</code></span>
     */
    public static void setField(final String fieldName, final Object target, final Object value) {
        try {
            Method setMethod = setterMethod(fieldName, target.getClass());
            if (setMethod != null) {
                makeAccessible(setMethod);
                setMethod.invoke(target, value);
            } else {
                Field field = getFieldIfAvailable(target.getClass(), fieldName);
                if (field != null) {
                    makeAccessible(field);
                    setField(field, target, value);
                }
            }
        } catch (Exception e) {
            if (ReflectionUtils.LOGGER.isDebugEnabled()) {
                ReflectionUtils.LOGGER.debug("Set_Value_Reflection_Error", e, fieldName,
                        Optional.ofNullable(value)
                                .map(val -> val.getClass().getName()).orElse(Globals.DEFAULT_VALUE_STRING));
            }
        }
    }

    /**
     * <h2 class="en-US">Callback interface invoked on each method in the hierarchy.</h2>
     * <h2 class="zh-CN">在层次结构中的每个方法上调用回调接口。</h2>
     *
     * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
     * @version $Revision: 1.0.0 $ $Date: Jan 15, 2010 10:27:42 $
     */
    public interface MethodCallback {
        /**
         * <h3 class="en-US">Perform an operation using the given method.</h3>
         * <h3 class="zh-CN">使用给定方法执行操作。</h3>
         *
         * @param method <span class="en-US">the method to operate on</span>
         *               <span class="zh-CN">要操作的方法</span>
         * @throws IllegalArgumentException <span class="en-US">If an error occurs when invoke doWith</span>
         *                                  <span class="zh-CN">如果调用doWith时出现错误</span>
         * @see java.lang.IllegalArgumentException
         */
        void doWith(Method method) throws IllegalArgumentException;
    }

    /**
     * <h2 class="en-US">Callback interface invoked on each field in the hierarchy.</h2>
     * <h2 class="zh-CN">在层次结构中的每个字段上调用回调接口。</h2>
     *
     * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
     * @version $Revision: 1.0.0 $ $Date: Jan 15, 2010 10:29:21 $
     */
    public interface FieldCallback {
        /**
         * <h3 class="en-US">Perform an operation using the given field.</h3>
         * <h3 class="zh-CN">使用给定属性执行操作。</h3>
         *
         * @param field <span class="en-US">the field to operate on</span>
         *              <span class="zh-CN">要操作的属性</span>
         * @throws IllegalArgumentException <span class="en-US">If an error occurs when invoke doWith</span>
         *                                  <span class="zh-CN">如果调用doWith时出现错误</span>
         * @throws IllegalAccessException   <span class="en-US">If an error occurs when invoke doWith</span>
         *                                  <span class="zh-CN">如果调用doWith时出现错误</span>
         * @see java.lang.IllegalArgumentException
         * @see java.lang.IllegalAccessException
         */
        void doWith(Field field) throws IllegalArgumentException, IllegalAccessException;
    }

    /**
     * <h2 class="en-US">Callback optionally used to filter members to be operated on by a member callback.</h2>
     * <h2 class="zh-CN">回调可选地用于过滤要由成员回调操作的成员。</h2>
     *
     * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
     * @version $Revision: 1.0.0 $ $Date: Jan 15, 2010 10:30:15 $
     */
    public interface MemberFilter {
        /**
         * <h3 class="en-US">Determine whether the given member matches.</h3>
         * <h3 class="zh-CN">确定给定成员是否匹配。</h3>
         *
         * @param member <span class="en-US">the member to check</span>
         *               <span class="zh-CN">要检查的成员</span>
         * @return <span class="en-US">check result</span>
         * <span class="zh-CN">检查结果</span>
         */
        boolean matches(final Member member);
    }

    /**
     * <h2 class="en-US">Callback optionally used to filter classes to be operated on super class.</h2>
     * <h2 class="zh-CN">回调可选地用于过滤要在超类上操作的类。</h2>
     *
     * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
     * @version $Revision: 1.0.0 $ $Date: Jan 15, 2010 10:31:08 $
     */
    public interface ClassFilter {
        /**
         * <h3 class="en-US">Determine whether the given class matches.</h3>
         * <h3 class="zh-CN">确定给定类是否匹配。</h3>
         *
         * @param clazz <span class="en-US">the class to check</span>
         *              <span class="zh-CN">要检查的类</span>
         * @return <span class="en-US">check result</span>
         * <span class="zh-CN">检查结果</span>
         */
        boolean matches(Class<?> clazz);
    }

    /**
     * <h2 class="en-US">Pre-build ClassFilter that matches classes was annotation by anyone of given Annotation class array.</h2>
     * <h2 class="zh-CN">匹配类的预构建 ClassFilter 是由给定 Annotation 类数组的任何一个进行注释的。</h2>
     *
     * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
     * @version $Revision: 1.0.0 $ $Date: Jan 15, 2010 10:33:28 $
     */
    public static final class AnnotationClassFilter implements ClassFilter {
        /**
         * <span class="en-US">Annotation class array</span>
         * <span class="zh-CN">Annotation 类数组</span>
         */
        private final List<Class<? extends Annotation>> annotations;

        /**
         * <h3 class="en-US">Constructor for AnnotationClassFilter</h3>
         * <h3 class="zh-CN">注解类过滤器的构造方法</h3>
         *
         * @param annotations <span class="en-US">Annotation class array</span>
         *                    <span class="zh-CN">Annotation 类数组</span>
         */
        public AnnotationClassFilter(final Class<? extends Annotation>[] annotations) {
            this.annotations = annotations == null ? Collections.emptyList() : Arrays.asList(annotations);
        }

        /**
         * (Non-Javadoc)
         *
         * @see ClassFilter#matches(Class)
         */
        @Override
        public boolean matches(final Class<?> clazz) {
            if (clazz == null) {
                return Boolean.FALSE;
            }
            if (this.annotations.isEmpty()) {
                return Boolean.TRUE;
            }
            return this.annotations.stream().anyMatch(clazz::isAnnotationPresent);
        }
    }

    /**
     * <span class="en-US">Pre-built MemberFilter that matches all non-static, non-final members.</span>
     * <span class="zh-CN">预构建的 MemberFilter 匹配所有非静态、非最终成员。</span>
     */
    public static final MemberFilter NON_STATIC_FINAL_MEMBERS = member -> !(staticMember(member) || finalMember(member));

    /**
     * <h3 class="en-US">Throws an IllegalStateException with the given exception as root cause.</h3>
     * <h3 class="zh-CN">抛出异常 IllegalStateException，并将给定异常作为根本原因。</h3>
     *
     * @param ex <span class="en-US">the unexpected exception</span>
     *           <span class="zh-CN">意外的异常</span>
     */
    private static void handleUnexpectedException(final Throwable ex) {
        // Needs to avoid the chained constructor for JDK 1.4 compatibility.
        throw new IllegalStateException("Unexpected exception thrown", ex);
    }

    /**
     * <h3 class="en-US">Find method</h3>
     * <h3 class="en-US">查找方法实例</h3>
     *
     * @param fieldName   <span class="en-US">Field name</span>
     *                    <span class="zh-CN">属性名</span>
     * @param targetClass <span class="en-US">Target class instance</span>
     *                    <span class="zh-CN">目标类实例</span>
     * @param methodType  <span class="en-US">Method type</span>
     *                    <span class="zh-CN">方法类型</span>
     * @return <span class="en-US">the Method object, or <code>null</code> if none found</span>
     * <span class="zh-CN">Method 对象，如果没有找到则为 <code>null</code></span>
     */
    private static Method findMethod(final String fieldName, final Class<?> targetClass, final MethodType methodType) {
        Field field = ReflectionUtils.getFieldIfAvailable(targetClass, fieldName);
        if (field == null) {
            return null;
        }
        return findMethod(targetClass, methodName(field, methodType),
                MethodType.Setter.equals(methodType) ? new Class<?>[]{field.getType()} : new Class[0]);
    }

    /**
     * <h3 class="en-US">Generate method name</h3>
     * <h3 class="en-US">生成方法名称</h3>
     *
     * @param field      <span class="en-US">Field instance</span>
     *                   <span class="zh-CN">属性实例对象</span>
     * @param methodType <span class="en-US">Method type</span>
     *                   <span class="zh-CN">方法类型</span>
     * @return <span class="en-US">Generated method name</span>
     * <span class="zh-CN">生成的方法名称</span>
     */
    private static String methodName(final Field field, final MethodType methodType) {
        StringBuilder methodName = new StringBuilder();
        switch (methodType) {
            case Getter:
                if (boolean.class.equals(field.getType())) {
                    methodName.append("is");
                } else {
                    methodName.append("get");
                }
                break;
            case Setter:
                methodName.append("set");
                break;
            default:
                return Globals.DEFAULT_VALUE_STRING;
        }
        String fieldName = field.getName();
        methodName.append(fieldName.substring(0, 1).toUpperCase()).append(fieldName.substring(1));
        return methodName.toString();
    }

    /**
     * <h3 class="en-US">Invoke the given callback on all fields in the target class, going up the class hierarchy to get all declared fields.</h3>
     * <h3 class="zh-CN">对目标类中的所有字段调用给定的回调，沿类层次结构向上获取所有声明的字段。</h3>
     *
     * @param targetClass  <span class="en-US">Target class</span>
     *                     <span class="zh-CN">目标类</span>
     * @param callback     <span class="en-US">given callback</span>
     *                     <span class="zh-CN">给定的回调</span>
     * @param doParent     <span class="en-US">Process parent class</span>
     *                     <span class="zh-CN">处理父类</span>
     * @param classFilter  <span class="en-US">Parent class filter (maybe <code>null</code> for process all parent class)</span>
     *                     <span class="zh-CN">父类过滤器（当为<code>null</code>时处理所有父类）</span>
     * @param memberFilter <span class="en-US">Field filter (maybe <code>null</code> for process callback at all fields)</span>
     *                     <span class="zh-CN">属性过滤器（当为<code>null</code>时为所有的属性执行回调）</span>
     * @throws IllegalArgumentException <span class="en-US">If an error occurs when invoke callback</span>
     *                                  <span class="zh-CN">如果调用回调时出现错误</span>
     * @throws IllegalAccessException   <span class="en-US">If an error occurs when invoke callback</span>
     *                                  <span class="zh-CN">如果调用回调时出现错误</span>
     */
    private static void doWithFields(Class<?> targetClass, final FieldCallback callback, final boolean doParent,
                                     final ClassFilter classFilter, final MemberFilter memberFilter)
            throws IllegalArgumentException, IllegalAccessException {
        // Keep backing up the inheritance hierarchy.
        do {
            // Copy each field declared on this class unless it's static or file.
            Field[] fields = targetClass.getDeclaredFields();
            for (Field field : fields) {
                // Skip static and final fields.
                if (memberFilter == null || memberFilter.matches(field)) {
                    callback.doWith(field);
                }
            }
            if (doParent) {
                if (classFilter == null) {
                    targetClass = targetClass.getSuperclass();
                } else {
                    do {
                        targetClass = targetClass.getSuperclass();
                    } while (targetClass != null && !classFilter.matches(targetClass));
                }
            } else {
                break;
            }
        }
        while (targetClass != null && !Object.class.equals(targetClass));
    }

    /**
     * <h3 class="en-US">Perform the given callback operation on all matching methods of the given class and superclasses.</h3>
     * <span class="en-US">
     * The same named method occurring on subclass and superclass will appear twice,
     * unless excluded by the specified argument memberFilter.
     * </span>
     * <h3 class="zh-CN">对给定类和超类的所有匹配方法执行给定的回调操作。</h3>
     * <span class="zh-CN">子类和超类上出现的相同命名方法将出现两次，除非被指定的参数 memberFilter 排除</span>
     *
     * @param targetClass  <span class="en-US">Target class</span>
     *                     <span class="zh-CN">目标类</span>
     * @param callback     <span class="en-US">given callback</span>
     *                     <span class="zh-CN">给定的回调</span>
     * @param doParent     <span class="en-US">Process parent class</span>
     *                     <span class="zh-CN">处理父类</span>
     * @param classFilter  <span class="en-US">Parent class filter (maybe <code>null</code> for process all parent class)</span>
     *                     <span class="zh-CN">父类过滤器（当为<code>null</code>时处理所有父类）</span>
     * @param memberFilter <span class="en-US">Field filter (maybe <code>null</code> for process callback at all fields)</span>
     *                     <span class="zh-CN">属性过滤器（当为<code>null</code>时为所有的属性执行回调）</span>
     * @throws IllegalArgumentException <span class="en-US">If an error occurs when invoke callback</span>
     *                                  <span class="zh-CN">如果调用回调时出现错误</span>
     */
    private static void doWithMethods(Class<?> targetClass, final MethodCallback callback, final boolean doParent,
                                      final ClassFilter classFilter, final MemberFilter memberFilter)
            throws IllegalArgumentException {
        // Keep backing up the inheritance hierarchy.
        do {
            for (Method method : targetClass.getDeclaredMethods()) {
                if (memberFilter == null || memberFilter.matches(method)) {
                    callback.doWith(method);
                }
            }
            if (doParent) {
                if (classFilter == null) {
                    targetClass = targetClass.getSuperclass();
                } else {
                    do {
                        targetClass = targetClass.getSuperclass();
                    } while (targetClass != null && !classFilter.matches(targetClass));
                }
            } else {
                break;
            }
        }
        while (targetClass != null);
    }

    /**
     * <h2 class="en-US">Enumeration of method type</h2>
     * <h2 class="en-US">方法类型的枚举</h2>
     */
    private enum MethodType {
        Getter, Setter
    }
}
