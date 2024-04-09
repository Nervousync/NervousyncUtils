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

package org.nervousync.enumerations.web;

/**
 * <h2 class="en-US">网络服务类型</h2>
 * <h2 class="zh-CN">Web Service类型</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 24, 2023 10:21:02 $
 */
public enum ServiceType {
	/**
	 * <span class="en-US">Simple Object Access Protocol</span>
	 * <span class="zh-CN">简单对象访问协议</span>
	 */
    SOAP,
	/**
	 * <span class="en-US">Representational State Transfer</span>
	 * <span class="zh-CN">属性状态传递格式的协议</span>
	 */
    Restful
}
