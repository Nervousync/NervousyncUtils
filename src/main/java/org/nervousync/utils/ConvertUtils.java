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

import java.io.*;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;

/**
 * <h2 class="en-US">Data convert utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Convert data bytes to hex string</ul>
 *     <ul>Convert data bytes to string</ul>
 *     <ul>Convert data bytes to Object</ul>
 *     <ul>Convert any to data bytes</ul>
 *     <ul>Convert properties to data map</ul>
 * </span>
 * <h2 class="zh-CN">数据转换工具集</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>转换字节数组为十六进制字符串</ul>
 *     <ul>转换字节数组为字符串</ul>
 *     <ul>转换字节数组为实例对象</ul>
 *     <ul>转换任意实例对象为字节数组</ul>
 *     <ul>转换属性信息为数据映射表</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Jan 12, 2010 15:12:05 $
 */
public final class ConvertUtils {
    /**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
     */
    private final static LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(ConvertUtils.class);

    /**
     * <h3 class="en-US">Private constructor for ConvertUtils</h3>
     * <h3 class="zh-CN">数据转换工具集的私有构造方法</h3>
     */
    private ConvertUtils() {
    }

    /**
     * <h3 class="en-US">Convert data byte array to hex string</h3>
     * <h3 class="zh-CN">转换二进制数组为十六进制字符串</h3>
     *
     * @param dataBytes <span class="en-US">the original data byte array</span>
     *                  <span class="zh-CN">原始二进制数组</span>
     * @return <span class="en-US">Converted hex string</span>
     * <span class="zh-CN">转换后的十六进制字符串</span>
     */
    public static String toHex(final byte[] dataBytes) {
        if (dataBytes == null) {
            return Globals.DEFAULT_VALUE_STRING;
        }
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : dataBytes) {
            String tmp = Integer.toHexString(b & 0xFF);
            if (tmp.length() == 1) {
                stringBuilder.append("0");
            }
            stringBuilder.append(tmp);
        }
        return stringBuilder.toString();
    }

    /**
     * <h3 class="en-US">Convert data byte array to string using default encoding: UTF-8</h3>
     * <h3 class="zh-CN">转换二进制数组为字符串，使用默认编码集：UTF-8</h3>
     *
     * @param dataBytes <span class="en-US">the original data byte array</span>
     *                  <span class="zh-CN">原始二进制数组</span>
     * @return <span class="en-US">Converted string</span>
     * <span class="zh-CN">转换后的字符串</span>
     */
    public static String toString(final byte[] dataBytes) {
        return toString(dataBytes, Globals.DEFAULT_ENCODING);
    }

    /**
     * <h3 class="en-US">Convert data byte array to string using given encoding</h3>
     * <h3 class="zh-CN">转换二进制数组为字符串，使用给定的编码集</h3>
     *
     * @param dataBytes <span class="en-US">the original data byte array</span>
     *                  <span class="zh-CN">原始二进制数组</span>
     * @param encoding  <span class="en-US">the charset encoding</span>
     *                  <span class="zh-CN">字符集</span>
     * @return <span class="en-US">Converted string</span>
     * <span class="zh-CN">转换后的字符串</span>
     */
    public static String toString(final byte[] dataBytes, final String encoding) {
        try {
            return new String(dataBytes, encoding);
        } catch (UnsupportedEncodingException ex) {
            return new String(dataBytes, Charset.defaultCharset());
        }
    }

    /**
     * <h3 class="en-US">Convert given string to data byte array using default encoding: UTF-8</h3>
     * <h3 class="zh-CN">转换字符串为二进制数组，使用默认编码集：UTF-8</h3>
     *
     * @param content <span class="en-US">the original string</span>
     *                <span class="zh-CN">原始字符串</span>
     * @return <span class="en-US">Converted data byte array</span>
     * <span class="zh-CN">转换后的二进制数组</span>
     */
    public static byte[] toByteArray(final String content) {
        return toByteArray(content, Globals.DEFAULT_ENCODING);
    }

    /**
     * <h3 class="en-US">Convert string to data byte array using given encoding</h3>
     * <h3 class="zh-CN">转换字符串为二进制数组，使用给定的编码集</h3>
     *
     * @param content  <span class="en-US">the original string</span>
     *                 <span class="zh-CN">原始字符串</span>
     * @param encoding <span class="en-US">the charset encoding</span>
     *                 <span class="zh-CN">字符集</span>
     * @return <span class="en-US">Converted data byte array</span>
     * <span class="zh-CN">转换后的二进制数组</span>
     */
    public static byte[] toByteArray(final String content, final String encoding) {
        try {
            return content.getBytes(encoding);
        } catch (UnsupportedEncodingException ex) {
            return content.getBytes(Charset.defaultCharset());
        }
    }

    /**
     * <h3 class="en-US">Convert given object instance to data byte array</h3>
     * <h3 class="zh-CN">转换实例对象为二进制数组</h3>
     *
     * @param object <span class="en-US">the object instance</span>
     *               <span class="zh-CN">换实例对象</span>
     * @return <span class="en-US">Converted data byte array</span>
     * <span class="zh-CN">转换后的二进制数组</span>
     */
    public static byte[] toByteArray(final Object object) {
        if (object == null) {
            return new byte[0];
        }
        if (object instanceof String) {
            return toByteArray((String) object);
        }

        if (object instanceof byte[] || object instanceof Byte[]) {
            assert object instanceof byte[];
            return (byte[]) object;
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream)) {
            outputStream = new ByteArrayOutputStream();
            objectOutputStream.writeObject(object);
            return outputStream.toByteArray();
        } catch (Exception e) {
            LOGGER.error("Convert_Object_To_Array_Error");
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Stack_Message_Error", e);
            }
        } finally {
            IOUtils.closeStream(outputStream);
        }

        return new byte[0];
    }

    /**
     * <h3 class="en-US">Convert given data mapping instance to object instance</h3>
     * <h3 class="zh-CN">转换数据映射表为实例对象</h3>
     *
     * @param <T>       <span class="en-US">define class</span>
     *                  <span class="zh-CN">定义类</span>
     * @param beanClass <span class="en-US">define class</span>
     *                  <span class="zh-CN">定义类</span>
     * @param dataMap   <span class="en-US">Data mapping instance</span>
     *                  <span class="zh-CN">数据映射表</span>
     *
     * @return <span class="en-US">Converted object instance</span>
     * <span class="zh-CN">转换后的对象实例</span>
     */
    public static <T> T toObject(final Class<T> beanClass, final Map<String, Object> dataMap) {
        return Optional.ofNullable(ObjectUtils.newInstance(beanClass))
                .map(object -> {
                    BeanUtils.copyData(dataMap, object);
                    return object;
                })
                .orElse(null);
    }

    /**
     * <h3 class="en-US">Convert given data byte array instance to object instance</h3>
     * <h3 class="zh-CN">转换二进制数组为实例对象</h3>
     *
     * @param dataBytes <span class="en-US">the original data byte array</span>
     *                  <span class="zh-CN">原始二进制数组</span>
     * @return <span class="en-US">Converted object instance</span>
     * <span class="zh-CN">转换后的实例对象</span>
     */
    public static Object toObject(final byte[] dataBytes) {
        if (dataBytes.length == 0) {
            return null;
        }

        ByteArrayInputStream byteInputStream = null;
        ObjectInputStream objectInputStream = null;
        try {
            byteInputStream = new ByteArrayInputStream(dataBytes);
            objectInputStream = new ObjectInputStream(byteInputStream);

            return objectInputStream.readObject();
        } catch (Exception e) {
            return dataBytes;
        } finally {
            IOUtils.closeStream(objectInputStream);
            IOUtils.closeStream(byteInputStream);
        }
    }

    /**
     * <h3 class="en-US">Read properties file and convert data to hash map</h3>
     * <h3 class="zh-CN">读取属性文件并转换数据为哈希表</h3>
     *
     * @param propertiesFilePath <span class="en-US">The properties file path</span>
     *                           <span class="zh-CN">属性文件地址</span>
     * @return <span class="en-US">Data hash map</span>
     * <span class="zh-CN">数据哈希表</span>
     */
    public static Map<String, String> toMap(final String propertiesFilePath) {
        return toMap(propertiesFilePath, null);
    }

    /**
     * <h3 class="en-US">Read properties file and merge data with given hash map</h3>
     * <h3 class="zh-CN">读取属性文件并将数据与给定的哈希表合并</h3>
     *
     * @param propertiesFilePath <span class="en-US">The properties file path</span>
     *                           <span class="zh-CN">属性文件地址</span>
     * @param messageMap         <span class="en-US">The merged data hash map</span>
     *                           <span class="zh-CN">要合并的数据哈希表</span>
     * @return <span class="en-US">Merged data hash map</span>
     * <span class="zh-CN">合并后的数据哈希表</span>
     */
    public static Map<String, String> toMap(final String propertiesFilePath, final Map<String, String> messageMap) {
        return toMap(PropertiesUtils.loadProperties(propertiesFilePath), messageMap);
    }

    /**
     * <h3 class="en-US">Read properties file from URL instance and convert data to hash map</h3>
     * <h3 class="zh-CN">从URL实例对象读取属性文件并转换数据为哈希表</h3>
     *
     * @param url <span class="en-US">The url instance of properties file</span>
     *            <span class="zh-CN">属性文件的URL实例对象</span>
     * @return <span class="en-US">Data hash map</span>
     * <span class="zh-CN">数据哈希表</span>
     */
    public static Map<String, String> toMap(final URL url) {
        return toMap(url, null);
    }

    /**
     * <h3 class="en-US">Read properties file from URL instance and merge data with given hash map</h3>
     * <h3 class="zh-CN">从URL实例对象读取属性文件并将数据与给定的哈希表合并</h3>
     *
     * @param url        <span class="en-US">The url instance of properties file</span>
     *                   <span class="zh-CN">属性文件的URL实例对象</span>
     * @param messageMap <span class="en-US">The merged data hash map</span>
     *                   <span class="zh-CN">要合并的数据哈希表</span>
     * @return <span class="en-US">Merged data hash map</span>
     * <span class="zh-CN">合并后的数据哈希表</span>
     */
    public static Map<String, String> toMap(final URL url, Map<String, String> messageMap) {
        return toMap(PropertiesUtils.loadProperties(url), messageMap);
    }

    /**
     * <h3 class="en-US">Convert properties instance to hash map and merge data with given hash map</h3>
     * <h3 class="zh-CN">转换属性实例对象为哈希表并将数据与给定的哈希表合并</h3>
     *
     * @param properties <span class="en-US">The properties instance</span>
     *                   <span class="zh-CN">属性实例对象</span>
     * @return <span class="en-US">Merged data hash map</span>
     * <span class="zh-CN">合并后的数据哈希表</span>
     */
    public static Map<String, String> toMap(final Properties properties) {
        return toMap(properties, null);
    }

    /**
     * <h3 class="en-US">Convert properties instance to hash map and merge data with given hash map</h3>
     * <h3 class="zh-CN">转换属性实例对象为哈希表并将数据与给定的哈希表合并</h3>
     *
     * @param properties <span class="en-US">The properties instance</span>
     *                   <span class="zh-CN">属性实例对象</span>
     * @param messageMap <span class="en-US">The merged data hash map</span>
     *                   <span class="zh-CN">要合并的数据哈希表</span>
     * @return <span class="en-US">Merged data hash map</span>
     * <span class="zh-CN">合并后的数据哈希表</span>
     */
    public static Map<String, String> toMap(final Properties properties, final Map<String, String> messageMap) {
        final Map<String, String> dataMap = (messageMap == null) ? new HashMap<>() : messageMap;
        if (properties != null) {
            properties.forEach((key, value) -> dataMap.put((String) key, (String) value));
        }
        return dataMap;
    }
}
