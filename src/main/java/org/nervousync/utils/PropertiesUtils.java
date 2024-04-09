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

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Map;
import java.util.Properties;

/**
 * <h2 class="en-US">Properties utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Read properties from string/file path/URL instance/input stream</ul>
 *     <ul>Modify properties file</ul>
 *     <ul>Storage properties instance to target file path</ul>
 * </span>
 * <h2 class="zh-CN">属性文件工具集</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>从字符串/本地文件/网络文件/输入流中读取属性文件</ul>
 *     <ul>修改属性文件</ul>
 *     <ul>将属性文件保存到目标地址</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Jan 14, 2010 11:47:08 $
 */
public final class PropertiesUtils {
    /**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
     */
    private final static LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(PropertiesUtils.class);

    /**
     * <h3 class="en-US">Private constructor for PropertiesUtils</h3>
     * <h3 class="zh-CN">属性文件工具集的私有构造方法</h3>
     */
    private PropertiesUtils() {
    }

    /**
     * <h3 class="en-US">Read properties from string</h3>
     * <h3 class="zh-CN">从字符串读取属性文件</h3>
     *
     * @param content <span class="en-US">Properties information string</span>
     *                <span class="zh-CN">属性信息字符串</span>
     * @return <span class="en-US">Properties instance</span>
     * <span class="zh-CN">属性信息实例对象</span>
     */
    public static Properties readProperties(final String content) {
        Properties properties = new Properties();
        if (StringUtils.notBlank(content)) {
            try (InputStream inputStream =
                         new ByteArrayInputStream(content.getBytes(Charset.forName(Globals.DEFAULT_ENCODING)))) {
                if (content.startsWith("<")) {
                    properties.loadFromXML(inputStream);
                } else {
                    properties.load(inputStream);
                }
            } catch (IOException e) {
                properties = new Properties();
            }
        }
        return properties;
    }

    /**
     * <h3 class="en-US">Read properties from file path</h3>
     * <h3 class="zh-CN">从指定路径读取属性文件</h3>
     *
     * @param propertiesFilePath <span class="en-US">Properties file path</span>
     *                           <span class="zh-CN">属性文件路径</span>
     * @return <span class="en-US">Properties instance</span>
     * <span class="zh-CN">属性信息实例对象</span>
     */
    public static Properties loadProperties(final String propertiesFilePath) {
        try {
            URL url = FileUtils.getURL(propertiesFilePath);
            return loadProperties(url);
        } catch (Exception e) {
            return new Properties();
        }
    }

    /**
     * <h3 class="en-US">Read properties from URL instance</h3>
     * <h3 class="zh-CN">从网络路径读取属性文件</h3>
     *
     * @param url <span class="en-US">URL instance</span>
     *            <span class="zh-CN">网络路径</span>
     * @return <span class="en-US">Properties instance</span>
     * <span class="zh-CN">属性信息实例对象</span>
     */
    public static Properties loadProperties(final URL url) {
        InputStream inputStream = null;
        try {
            String fileName = url.getFile();
            String fileExtName = StringUtils.getFilenameExtension(fileName);
            inputStream = url.openStream();
            return loadProperties(inputStream, fileExtName.equalsIgnoreCase("xml"));
        } catch (Exception e) {
            LOGGER.error("Load_Properties_Error");
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Stack_Message_Error", e);
            }
            return new Properties();
        } finally {
            IOUtils.closeStream(inputStream);
        }
    }

    /**
     * <h3 class="en-US">Read properties from input stream.</h3>
     * <span class="en-US">Attention: users need to call the close method for input stream manually.</span>
     * <h3 class="zh-CN">从输入流中读取属性文件。</h3>
     * <span class="zh-CN">注意：用户必须手动调用输入流的 close 方法。</span>
     *
     * @param inputStream <span class="en-US">Input stream instance</span>
     *                    <span class="zh-CN">输入流实例对象</span>
     * @param isXML       <span class="en-US">Data is XML format</span>
     *                    <span class="zh-CN">数据是XML格式</span>
     * @return <span class="en-US">Properties instance</span>
     * <span class="zh-CN">属性信息实例对象</span>
     */
    public static Properties loadProperties(final InputStream inputStream, final boolean isXML) {
        Properties properties = new Properties();
        try {
            if (isXML) {
                properties.loadFromXML(inputStream);
            } else {
                properties.load(inputStream);
            }

            return properties;
        } catch (Exception e) {
            LOGGER.error("Load_Properties_Error");
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Stack_Message_Error", e);
            }
            return new Properties();
        }
    }

    /**
     * <h3 class="en-US">Modify properties file</h3>
     * <h3 class="zh-CN">修改属性文件</h3>
     *
     * @param propertiesFilePath <span class="en-US">Properties file path</span>
     *                           <span class="zh-CN">属性文件路径</span>
     * @param modifyMap          <span class="en-US">Modify data key-value map</span>
     *                           <span class="zh-CN">要修改的键值对数据表</span>
     * @param comment            <span class="en-US">Comment string</span>
     *                           <span class="zh-CN">备注字符串</span>
     * @return <span class="en-US">Process result</span>
     * <span class="zh-CN">处理结果</span>
     */
    public static boolean modifyProperties(final String propertiesFilePath, final Map<String, String> modifyMap,
                                           final String comment) {
        try {
            Properties modifyProperties = loadProperties(propertiesFilePath);
            modifyProperties(modifyProperties, modifyMap);
            return storeProperties(modifyProperties, propertiesFilePath, comment);
        } catch (Exception e) {
            LOGGER.error("Modify_Properties_Error");
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Stack_Message_Error", e);
            }
            return Boolean.FALSE;
        }
    }

    /**
     * <h3 class="en-US">Modify properties file</h3>
     * <h3 class="zh-CN">修改属性文件</h3>
     *
     * @param properties <span class="en-US">Properties instance</span>
     *                   <span class="zh-CN">属性信息实例对象</span>
     * @param modifyMap  <span class="en-US">Modify data key-value map</span>
     *                   <span class="zh-CN">要修改的键值对数据表</span>
     */
    public static void modifyProperties(final Properties properties, final Map<String, String> modifyMap) {
        modifyMap.forEach((key, value) ->
                properties.setProperty(key, StringUtils.isEmpty(value) ? Globals.DEFAULT_VALUE_STRING : value));
    }

    /**
     * <h3 class="en-US">Storage properties instance to target file path</h3>
     * <h3 class="zh-CN">将属性文件保存到目标地址</h3>
     *
     * @param properties         <span class="en-US">Properties instance</span>
     *                           <span class="zh-CN">属性信息实例对象</span>
     * @param propertiesFilePath <span class="en-US">Properties file path</span>
     *                           <span class="zh-CN">属性文件路径</span>
     * @param comment            <span class="en-US">Comment string</span>
     *                           <span class="zh-CN">备注字符串</span>
     * @return <span class="en-US">Process result</span>
     * <span class="zh-CN">处理结果</span>
     */
    private static boolean storeProperties(final Properties properties, final String propertiesFilePath,
                                           final String comment) {
        FileOutputStream fileOutputStream = null;
        try {
            String filePath = propertiesFilePath.substring(0,
                    propertiesFilePath.lastIndexOf(Globals.DEFAULT_PAGE_SEPARATOR));
            FileUtils.makeDir(filePath);
            String fileExtName = StringUtils.getFilenameExtension(propertiesFilePath);

            fileOutputStream = new FileOutputStream(propertiesFilePath, false);

            switch (fileExtName.toLowerCase()) {
                case "xml":
                    properties.storeToXML(fileOutputStream, comment, Globals.DEFAULT_ENCODING);
                    break;
                case "properties":
                    properties.store(fileOutputStream, comment);
                    break;
                default:
                    throw new Exception("Properties file error");
            }
            return Boolean.TRUE;
        } catch (Exception e) {
            LOGGER.error("Save_Properties_Error");
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Stack_Message_Error", e);
            }
            return Boolean.FALSE;
        } finally {
            IOUtils.closeStream(fileOutputStream);
        }
    }
}
