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
package org.nervousync.mail.operator;

import org.nervousync.mail.config.MailConfig;

import java.util.Properties;

/**
 * <h2 class="en-US">Interface class for e-mail send operator</h2>
 * <h2 class="zh-CN">电子邮件发送器的接口</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 10, 2019 15:49:52 $
 */
public interface SendOperator {
	/**
	 * <h3 class="en-US">Convert given e-mail server configure instance to Properties instance</h3>
	 * <p class="en-US">Generated Properties instance is using for connect to E-mail server </p>
	 * <h3 class="zh-CN">转换给定的电子邮件配置实例对象为Properties实例对象</h3>
	 * <p class="zh-CN">生成的Properties实例对象用于连接到电子邮件服务器</p>
	 *
	 * @param serverConfig <span class="en-US">Server configure information</span>
	 *                     <span class="zh-CN">服务器配置</span>
	 * @return <span class="en-US">Generated Properties instance</span>
	 * <span class="zh-CN">生成的Properties实例对象</span>
	 */
	Properties readConfig(final MailConfig.ServerConfig serverConfig);

}
