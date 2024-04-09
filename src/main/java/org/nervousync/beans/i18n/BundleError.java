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

/**
 * <h2 class="en-US">Internationalization Error Data</h2>
 * <h2 class="zh-CN">国际化错误信息</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 19, 2023 16:47:31 $
 */
@OutputConfig(type = StringUtils.StringType.JSON)
public final class BundleError extends BeanObject {

    /**
     * <span class="en-US">Serial version UID</span>
     * <span class="zh-CN">序列化UID</span>
     */
    private static final long serialVersionUID = -3619612208409411199L;

    /**
     * <span class="en-US">Error code</span>
     * <span class="zh-CN">错误代码</span>
     */
    @JsonProperty("code")
    private String errorCode = Globals.DEFAULT_VALUE_STRING;
    /**
     * <span class="en-US">Message identify key</span>
     * <span class="zh-CN">信息识别键值</span>
     */
    @JsonProperty("key")
    private String messageKey = Globals.DEFAULT_VALUE_STRING;

    /**
     * <h3 class="en-US">Constructor for internationalization error data</h3>
     * <h3 class="zh-CN">国际化错误信息的构造方法</h3>
     */
    public BundleError() {
    }

    /**
     * <h3 class="en-US">Getter method for error code</h3>
     * <h3 class="zh-CN">错误代码的Getter方法</h3>
     *
     * @return <span class="en-US">Error code</span>
     * <span class="zh-CN">错误代码</span>
     */
    public String getErrorCode() {
        return errorCode;
    }

    /**
     * <h3 class="en-US">Setter method for error code</h3>
     * <h3 class="zh-CN">错误代码的Setter方法</h3>
     *
     * @param errorCode <span class="en-US">Error code</span>
     *                  <span class="zh-CN">错误代码</span>
     */
    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    /**
     * <h3 class="en-US">Getter method for message identify key</h3>
     * <h3 class="zh-CN">信息识别键值的Getter方法</h3>
     *
     * @return <span class="en-US">Message identify key</span>
     * <span class="zh-CN">信息识别键值</span>
     */
    public String getMessageKey() {
        return messageKey;
    }

    /**
     * <h3 class="en-US">Setter method for message identify key</h3>
     * <h3 class="zh-CN">信息识别键值的Setter方法</h3>
     *
     * @param messageKey <span class="en-US">Message identify key</span>
     *                   <span class="zh-CN">信息识别键值</span>
     */
    public void setMessageKey(String messageKey) {
        this.messageKey = messageKey;
    }
}
