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

import jakarta.xml.bind.annotation.XmlRootElement;
import org.nervousync.annotations.beans.OutputConfig;
import org.nervousync.annotations.configs.Password;
import org.nervousync.beans.core.BeanObject;
import org.nervousync.commons.Globals;
import org.nervousync.security.factory.SecureFactory;
import org.nervousync.utils.*;

import java.io.FileNotFoundException;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * <h2 class="en-US">Configuration Information Manager</h2>
 * <h2 class="zh-CN">配置信息管理器</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Oct 09, 2023 09:48:31 $
 */
public final class ConfigureManager {
    /**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
     */
    private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(ConfigureManager.class);
    /**
     * <span class="en-US">Singleton instance</span>
     * <span class="zh-CN">单一实例对象</span>
     */
    private static ConfigureManager INSTANCE = null;
    /**
     * <span class="en-US">Configuration information storage path</span>
     * <span class="zh-CN">配置信息存储路径</span>
     */
    private final String basePath;
    /**
     * <span class="en-US">Mapping table of scanned configuration file names and paths</span>
     * <span class="zh-CN">扫描到的配置文件名与路径的映射表</span>
     */
    private final Hashtable<String, String> existsFiles;
    /**
     * <span class="en-US">The mapping table between passwords and security configuration names is saved in the configuration file.</span>
     * <span class="zh-CN">配置文件中保存密码与安全配置名称的映射表</span>
     */
    private final Hashtable<String, Map<String, String>> securityFieldsMap;
    /**
     * <span class="en-US">Scheduled task service</span>
     * <span class="zh-CN">定时调度任务服务</span>
     */
    private final ScheduledExecutorService scheduledExecutorService;
    /**
     * <span class="en-US">Scheduled task running status</span>
     * <span class="zh-CN">定时调度任务执行状态</span>
     */
    private boolean running = Boolean.FALSE;

    static {
        initialize();
    }

    /**
     * <h3 class="en-US">Private constructor for Configuration Information Manager</h3>
     * <h3 class="zh-CN">配置信息管理器的私有构造方法</h3>
     *
     * @param basePath <span class="en-US">Configuration information storage path</span>
     *                 <span class="zh-CN">配置信息存储路径</span>
     */
    private ConfigureManager(final String basePath) {
        this.basePath = basePath;
        this.existsFiles = new Hashtable<>();
        this.securityFieldsMap = new Hashtable<>();
        this.scanFiles();
        this.scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
        this.scheduledExecutorService.scheduleAtFixedRate(this::scanFiles, Globals.DEFAULT_SCHEDULE_DELAY,
                Globals.DEFAULT_SCHEDULE_PERIOD, TimeUnit.MILLISECONDS);
    }

    /**
     * <h3 class="en-US">Static method for retrieve singleton instance of Configuration Information Manager</h3>
     * <h3 class="zh-CN">静态方法用于获取配置信息管理器单例实例对象</h3>
     *
     * @return <span class="en-US">Singleton instance</span>
     * <span class="zh-CN">单例实例对象</span>
     */
    public static ConfigureManager getInstance() {
        return INSTANCE;
    }

    /**
     * <h3 class="en-US">Initialize Configuration Information Manager</h3>
     * <h3 class="zh-CN">初始化配置信息管理器</h3>
     */
    public static void initialize() {
        initialize(Globals.DEFAULT_VALUE_STRING);
    }

    /**
     * <h3 class="en-US">Initialize Configuration Information Manager</h3>
     * <h3 class="zh-CN">初始化配置信息管理器</h3>
     *
     * @param customPath <span class="en-US">Configuration information storage path</span>
     *                   <span class="zh-CN">配置信息存储路径</span>
     */
    public static void initialize(final String customPath) {
        boolean registerHook = Boolean.TRUE;
        if (INSTANCE != null) {
            destroy();
            registerHook = Boolean.FALSE;
        }
        String storagePath;
        if (StringUtils.isEmpty(customPath)) {
            storagePath = SystemUtils.USER_HOME;
            if (StringUtils.isEmpty(storagePath)) {
                LOGGER.error("Configure_Manager_Path_Null");
                return;
            }
            storagePath += (Globals.DEFAULT_PAGE_SEPARATOR + "configs");
        } else {
            storagePath = customPath;
        }
        if (!FileUtils.isExists(storagePath)) {
            FileUtils.makeDir(storagePath);
        }
        if (!FileUtils.isDirectory(storagePath)) {
            LOGGER.error("Configure_Manager_Path_Not_Exists", storagePath);
            return;
        }
        INSTANCE = new ConfigureManager(storagePath);
        if (registerHook) {
            Runtime.getRuntime().addShutdownHook(new Thread(ConfigureManager::destroy));
        }
    }

    /**
     * <h3 class="en-US">Destroy the initialized configuration information manager</h3>
     * <h3 class="zh-CN">销毁初始化的配置信息管理器</h3>
     */
    private static void destroy() {
        if (INSTANCE != null) {
            INSTANCE.shutdown();
            INSTANCE = null;
        }
    }

    private void shutdown() {
        this.scheduledExecutorService.shutdown();
        this.existsFiles.clear();
    }

    /**
     * <h3 class="en-US">Read configuration information and convert it into instance object</h3>
     * <h3 class="zh-CN">读取配置信息并转换为实例对象</h3>
     *
     * @param targetClass <span class="en-US">Configuration information JavaBean class</span>
     *                    <span class="zh-CN">配置信息JavaBean类</span>
     * @param <T>         <span class="en-US">Configuration information JavaBean class</span>
     *                    <span class="zh-CN">配置信息JavaBean类</span>
     * @return <span class="en-US">Converted object instance</span>
     * <span class="zh-CN">转换后的实例对象</span>
     */
    public <T> T readConfigure(final Class<T> targetClass) {
        return this.readConfigure(targetClass, Globals.DEFAULT_VALUE_STRING);
    }

    /**
     * <h3 class="en-US">Read configuration information and convert it into instance object</h3>
     * <h3 class="zh-CN">读取配置信息并转换为实例对象</h3>
     *
     * @param targetClass <span class="en-US">Configuration information JavaBean class</span>
     *                    <span class="zh-CN">配置信息JavaBean类</span>
     * @param suffix      <span class="en-US">Configuration file custom suffix</span>
     *                    <span class="zh-CN">配置文件自定义后缀</span>
     * @param <T>         <span class="en-US">Configuration information JavaBean class</span>
     *                    <span class="zh-CN">配置信息JavaBean类</span>
     * @return <span class="en-US">Converted object instance</span>
     * <span class="zh-CN">转换后的实例对象</span>
     */
    public <T> T readConfigure(final Class<T> targetClass, final String suffix) {
        if (targetClass == null) {
            return null;
        }
        String fileName = this.parseName(targetClass, suffix);
        String schemaPath =
                Optional.ofNullable(targetClass.getAnnotation(XmlRootElement.class))
                        .filter(xmlRootElement ->
                                !Globals.DEFAULT_XML_ANNOTATION_NAME.equalsIgnoreCase(xmlRootElement.namespace()))
                        .map(XmlRootElement::namespace)
                        .orElse(Globals.DEFAULT_VALUE_STRING);
        if (!this.existsFiles.containsKey(fileName)) {
            return null;
        }
        T readConfig = StringUtils.fileToObject(this.existsFiles.get(fileName), targetClass, schemaPath);
        if (readConfig instanceof BeanObject) {
            this.securityFields((BeanObject) readConfig, Boolean.FALSE);
        }
        return readConfig;
    }

    /**
     * <h3 class="en-US">Save configuration information instance object data</h3>
     * <h3 class="zh-CN">保存配置信息实例对象数据</h3>
     *
     * @param beanObject <span class="en-US">Configuration information instance object</span>
     *                   <span class="zh-CN">配置信息实例对象</span>
     * @return <span class="en-US">Operate result</span>
     * <span class="zh-CN">操作结果</span>
     */
    public boolean saveConfigure(final BeanObject beanObject) {
        return this.saveConfigure(beanObject, Globals.DEFAULT_VALUE_STRING);
    }

    private void securityFields(final BeanObject beanObject, final boolean encrypt) {
        this.scanFields(beanObject.getClass());
        String className = ClassUtils.originalClassName(beanObject.getClass());
        Optional.ofNullable(this.securityFieldsMap.get(className))
                .ifPresent(fieldMap ->
                        fieldMap.forEach((fieldName, secureName) -> {
                            if (!SecureFactory.registeredConfig(secureName)) {
                                return;
                            }
                            Object fieldValue = ReflectionUtils.getFieldValue(fieldName, beanObject);
                            if (fieldValue instanceof BeanObject) {
                                this.securityFields((BeanObject) fieldValue, encrypt);
                                ReflectionUtils.setField(fieldName, beanObject, fieldValue);
                            } else if (StringUtils.notBlank(secureName) && fieldValue instanceof String) {
                                ReflectionUtils.setField(fieldName, beanObject, encrypt
                                        ? SecureFactory.encrypt(secureName, (String) fieldValue)
                                        : SecureFactory.decrypt(secureName, (String) fieldValue));
                            }
                        }));
    }

    /**
     * <h3 class="en-US">Save configuration information instance object data</h3>
     * <h3 class="zh-CN">保存配置信息实例对象数据</h3>
     *
     * @param beanObject <span class="en-US">Configuration information instance object</span>
     *                   <span class="zh-CN">配置信息实例对象</span>
     * @param suffix     <span class="en-US">Configuration file custom suffix</span>
     *                   <span class="zh-CN">配置文件自定义后缀</span>
     * @return <span class="en-US">Operate result</span>
     * <span class="zh-CN">操作结果</span>
     */
    public boolean saveConfigure(final BeanObject beanObject, final String suffix) {
        if (beanObject == null) {
            return Boolean.FALSE;
        }
        this.securityFields(beanObject, Boolean.TRUE);
        String fileName = this.parseName(beanObject.getClass(), suffix);
        String filePath = this.existsFiles.getOrDefault(fileName, Globals.DEFAULT_VALUE_STRING);
        StringUtils.StringType stringType;
        if (StringUtils.isEmpty(filePath)) {
            filePath = this.basePath + Globals.DEFAULT_PAGE_SEPARATOR + fileName;
            stringType = Optional.ofNullable(beanObject.getClass().getAnnotation(OutputConfig.class))
                    .map(OutputConfig::type)
                    .orElse(StringUtils.StringType.XML);
            switch (stringType) {
                case XML:
                    filePath += ".xml";
                    break;
                case JSON:
                    filePath += ".json";
                    break;
                case YAML:
                    filePath += ".yml";
                    break;
            }
        }
        if (FileUtils.saveFile(filePath, beanObject.toString())) {
            if (!this.existsFiles.containsKey(fileName)) {
                this.existsFiles.put(fileName, filePath);
            }
            return Boolean.TRUE;
        }
        return Boolean.FALSE;
    }

    /**
     * <h3 class="en-US">Delete all configuration files of type configuration information</h3>
     * <h3 class="zh-CN">删除所有类型为配置信息类的配置文件</h3>
     *
     * @param targetClass <span class="en-US">Configuration information JavaBean class</span>
     *                    <span class="zh-CN">配置信息JavaBean类</span>
     */
    public void removeConfigure(final Class<?> targetClass) {
        this.removeConfigure(targetClass, Globals.DEFAULT_VALUE_STRING);
    }

    /**
     * <h3 class="en-US">Delete configuration information</h3>
     * <span class="en-US">If the custom suffix is empty, delete all configuration files of type configuration information class.</span>
     * <h3 class="zh-CN">删除配置信息</h3>
     * <span class="zh-CN">如果自定义后缀为空则删除所有类型为配置信息类的配置文件</span>
     *
     * @param targetClass <span class="en-US">Configuration information JavaBean class</span>
     *                    <span class="zh-CN">配置信息JavaBean类</span>
     * @param suffix      <span class="en-US">Configuration file custom suffix</span>
     *                    <span class="zh-CN">配置文件自定义后缀</span>
     */
    public void removeConfigure(final Class<?> targetClass, final String suffix) {
        String fileName = this.parseName(targetClass, suffix);
        if (StringUtils.notBlank(fileName)) {
            Iterator<Map.Entry<String, String>> iterator = this.existsFiles.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, String> entry = iterator.next();
                if (entry.getKey().equalsIgnoreCase(fileName) || entry.getKey().startsWith(fileName)) {
                    FileUtils.removeFile(entry.getValue());
                    iterator.remove();
                }
            }
        }
    }

    /**
     * <h3 class="en-US">Parse profile name based on given object class and custom suffix</h3>
     * <h3 class="zh-CN">根据给定的对象类和自定义后缀解析配置文件名称</h3>
     *
     * @param clazz  <span class="en-US">Configuration information JavaBean class</span>
     *               <span class="zh-CN">配置信息实例类</span>
     * @param suffix <span class="en-US">Configuration file custom suffix</span>
     *               <span class="zh-CN">配置文件自定义后缀</span>
     * @return <span class="en-US">Parsed profile name</span>
     * <span class="zh-CN">解析的配置文件名称</span>
     */
    private String parseName(final Class<?> clazz, final String suffix) {
        String fileName = Globals.DEFAULT_XML_ANNOTATION_NAME;
        if (clazz.isAnnotationPresent(XmlRootElement.class)) {
            XmlRootElement xmlRootElement = clazz.getAnnotation(XmlRootElement.class);
            fileName = xmlRootElement.name();
        }
        if (Globals.DEFAULT_XML_ANNOTATION_NAME.equalsIgnoreCase(fileName)) {
            fileName = clazz.getSimpleName();
        }
        if (StringUtils.notBlank(suffix)) {
            fileName += ("_" + suffix);
        }
        return fileName;
    }

    /**
     * <h3 class="en-US">Scheduling tasks</h3>
     * <span class="en-US">Used to scan configuration information files existing in the configuration information storage path</span>
     * <h3 class="zh-CN">调度任务</h3>
     * <span class="zh-CN">用于扫描配置信息存储路径中存在的配置信息文件</span>
     */
    private void scanFiles() {
        if (this.running) {
            return;
        }
        this.running = Boolean.TRUE;
        try {
            List<String> existsPaths = FileUtils.listFiles(this.basePath);
            this.existsFiles.entrySet().removeIf(entry -> !existsPaths.contains(entry.getValue()));

            existsPaths.forEach(filePath -> {
                String fileName = StringUtils.getFilename(filePath);
                if (fileName.contains(".")) {
                    fileName = fileName.substring(0, fileName.lastIndexOf("."));
                }
                if (this.existsFiles.containsKey(fileName)) {
                    String existPath = this.existsFiles.get(fileName);
                    if (!ObjectUtils.nullSafeEquals(existPath, filePath)) {
                        LOGGER.warn("Configure_Manager_Override_Path", existPath, filePath);
                    }
                }
                this.existsFiles.put(fileName, filePath);
            });
        } catch (FileNotFoundException e) {
            LOGGER.error("Configure_Manager_Scan_Error", this.basePath);
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Stack_Message_Error", e);
            }
        }
        this.running = Boolean.FALSE;
    }

    private void scanFields(final Class<?> beanClass) {
        if (!ClassUtils.isAssignable(BeanObject.class, beanClass)) {
            return;
        }
        String className = ClassUtils.originalClassName(beanClass);
        if (this.securityFieldsMap.containsKey(className)) {
            return;
        }
        Map<String, String> fieldMap = new HashMap<>();
        ReflectionUtils.getAllDeclaredFields(beanClass)
                .forEach(field ->
                        fieldMap.put(field.getName(),
                                Optional.ofNullable(field.getAnnotation(Password.class))
                                        .map(Password::value)
                                        .filter(StringUtils::notBlank)
                                        .orElse(Globals.DEFAULT_VALUE_STRING)));
        this.securityFieldsMap.put(className, fieldMap);
    }
}
