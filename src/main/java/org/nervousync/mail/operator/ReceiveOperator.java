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

import jakarta.mail.Folder;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import org.nervousync.mail.config.MailConfig;

import java.util.List;
import java.util.Properties;

/**
 * <h2 class="en-US">Interface class for e-mail receive operator</h2>
 * <h2 class="zh-CN">电子邮件接收器的接口</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 10, 2019 15:47:26 $
 */
public interface ReceiveOperator {
	/**
	 * <h3 class="en-US">Read UID string by given folder and message instance</h3>
	 * <h3 class="zh-CN">根据给定的电子邮件目录实例对象和邮件信息实例对象读取唯一识别ID字符串</h3>
	 *
	 * @param folder  <span class="en-US">E-mail folder instance</span>
	 *                <span class="zh-CN">电子邮件目录实例对象</span>
	 * @param message <span class="en-US">E-mail message instance</span>
	 *                <span class="zh-CN">电子邮件信息实例对象</span>
	 * @return <span class="en-US">Read UID string</span>
	 * <span class="zh-CN">读取的唯一识别ID字符串</span>
	 * @throws MessagingException <span class="en-US">If an error occurs when read UID string</span>
	 *                            <span class="zh-CN">当读取唯一识别ID字符串时出现异常</span>
	 */
	String readUID(final Folder folder, final Message message) throws MessagingException;

	/**
	 * <h3 class="en-US">Read E-mail message by given folder and message UID string</h3>
	 * <h3 class="zh-CN">从给定的电子邮件目录中读取唯一识别ID字符串标识的电子邮件信息</h3>
	 *
	 * @param folder <span class="en-US">E-mail folder instance</span>
	 *               <span class="zh-CN">电子邮件目录实例对象</span>
	 * @param uid    <span class="en-US">UID string</span>
	 *               <span class="zh-CN">唯一标识ID字符串</span>
	 * @return <span class="en-US">Read e-mail message instance</span>
	 * <span class="zh-CN">读取的电子邮件信息实例对象</span>
	 * @throws MessagingException <span class="en-US">If an error occurs when read UID string</span>
	 *                            <span class="zh-CN">当读取唯一识别ID字符串时出现异常</span>
	 */
	Message readMessage(final Folder folder, final String uid) throws MessagingException;

	/**
	 * <h3 class="en-US">Read E-mail message list by given folder and message UID string array</h3>
	 * <h3 class="zh-CN">从给定的电子邮件目录中读取唯一识别ID字符串数组标识的电子邮件信息列表</h3>
	 *
	 * @param folder    <span class="en-US">E-mail folder instance</span>
	 *                  <span class="zh-CN">电子邮件目录实例对象</span>
	 * @param uidArrays <span class="en-US">UID string</span>
	 *                  <span class="zh-CN">唯一标识ID字符串</span>
	 * @return <span class="en-US">Read e-mail message instance list</span>
	 * <span class="zh-CN">读取的电子邮件信息实例对象列表</span>
	 * @throws MessagingException <span class="en-US">If an error occurs when read UID string</span>
	 *                            <span class="zh-CN">当读取唯一识别ID字符串时出现异常</span>
	 */
	List<Message> readMessages(final Folder folder, final String... uidArrays) throws MessagingException;

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
