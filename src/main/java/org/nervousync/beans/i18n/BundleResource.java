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

package org.nervousync.beans.i18n;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.nervousync.annotations.beans.OutputConfig;
import org.nervousync.beans.core.BeanObject;
import org.nervousync.commons.Globals;
import org.nervousync.utils.StringUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * <h2 class="en-US">Internationalization Resource Data</h2>
 * <h2 class="zh-CN">国际化资源数据</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 19, 2023 16:46:22 $
 */
@OutputConfig(type = StringUtils.StringType.JSON, formatted = true)
public final class BundleResource extends BeanObject {

    /**
     * <span class="en-US">Serial version UID</span>
     * <span class="zh-CN">序列化UID</span>
     */
    private static final long serialVersionUID = -6512620733960415512L;
    /**
     * <span class="en-US">Organization identification code</span>
     * <span class="zh-CN">组织识别代码</span>
     */
    private String groupId;
    /**
     * <span class="en-US">Project identification code</span>
     * <span class="zh-CN">项目识别代码</span>
     */
    private String bundle;
    /**
     * <span class="en-US">Definition list of error codes and message identification codes</span>
     * <span class="zh-CN">错误代码与信息识别代码的定义列表</span>
     */
    @JsonProperty("errors")
    private List<BundleError> bundleErrors;
    /**
     * <span class="en-US">List of definitions of message language, identification codes and message content</span>
     * <span class="zh-CN">信息语言、识别代码与信息内容的定义列表</span>
     */
    @JsonProperty("languages")
    private List<BundleLanguage> bundleLanguages;

    /**
     * <h3 class="en-US">Constructor for internationalization resource data</h3>
     * <h3 class="zh-CN">国际化资源数据的构造方法</h3>
     */
    public BundleResource() {
        this.groupId = Globals.DEFAULT_VALUE_STRING;
        this.bundle = Globals.DEFAULT_VALUE_STRING;
        this.bundleErrors = new ArrayList<>();
        this.bundleLanguages = new ArrayList<>();
    }

    /**
     * <h3 class="en-US">Getter method for organization identification code</h3>
     * <h3 class="zh-CN">组织识别代码的Getter方法</h3>
     *
     * @return <span class="en-US">Organization identification code</span>
     * <span class="zh-CN">组织识别代码</span>
     */
    public String getGroupId() {
        return groupId;
    }

    /**
     * <h3 class="en-US">Setter method for organization identification code</h3>
     * <h3 class="zh-CN">组织识别代码的Setter方法</h3>
     *
     * @param groupId <span class="en-US">Organization identification code</span>
     *                <span class="zh-CN">组织识别代码</span>
     */
    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }

    /**
     * <h3 class="en-US">Getter method for project identification code</h3>
     * <h3 class="zh-CN">项目识别代码的Getter方法</h3>
     *
     * @return <span class="en-US">Project identification code</span>
     * <span class="zh-CN">项目识别代码</span>
     */
    public String getBundle() {
        return bundle;
    }

    /**
     * <h3 class="en-US">Setter method for project identification code</h3>
     * <h3 class="zh-CN">项目识别代码的Setter方法</h3>
     *
     * @param bundle <span class="en-US">Project identification code</span>
     *               <span class="zh-CN">项目识别代码</span>
     */
    public void setBundle(String bundle) {
        this.bundle = bundle;
    }

    /**
     * <h3 class="en-US">Getter method for definition list of error codes and message identification codes</h3>
     * <h3 class="zh-CN">错误代码与信息识别代码的定义列表的Getter方法</h3>
     *
     * @return <span class="en-US">Definition list of error codes and message identification codes</span>
     * <span class="zh-CN">错误代码与信息识别代码的定义列表</span>
     */
    public List<BundleError> getBundleErrors() {
        return bundleErrors;
    }

    /**
     * <h3 class="en-US">Setter method for definition list of error codes and message identification codes</h3>
     * <h3 class="zh-CN">错误代码与信息识别代码的定义列表的Setter方法</h3>
     *
     * @param bundleErrors <span class="en-US">Definition list of error codes and message identification codes</span>
     *                     <span class="zh-CN">错误代码与信息识别代码的定义列表</span>
     */
    public void setBundleErrors(List<BundleError> bundleErrors) {
        this.bundleErrors = bundleErrors;
    }

    /**
     * <h3 class="en-US">Getter method for list of definitions of message language, identification codes and message content</h3>
     * <h3 class="zh-CN">信息语言、识别代码与信息内容的定义列表的Getter方法</h3>
     *
     * @return <span class="en-US">List of definitions of message language, identification codes and message content</span>
     * <span class="zh-CN">信息语言、识别代码与信息内容的定义列表</span>
     */
    public List<BundleLanguage> getBundleLanguages() {
        return bundleLanguages;
    }

    /**
     * <h3 class="en-US">Setter method for list of definitions of message language, identification codes and message content</h3>
     * <h3 class="zh-CN">信息语言、识别代码与信息内容的定义列表的Setter方法</h3>
     *
     * @param bundleLanguages <span class="en-US">List of definitions of message language, identification codes and message content</span>
     *                        <span class="zh-CN">信息语言、识别代码与信息内容的定义列表</span>
     */
    public void setBundleLanguages(List<BundleLanguage> bundleLanguages) {
        this.bundleLanguages = bundleLanguages;
    }
}
