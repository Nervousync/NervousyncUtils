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
package org.nervousync.mail.protocol.impl;

import jakarta.mail.Folder;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import org.eclipse.angus.mail.pop3.POP3Folder;
import org.nervousync.commons.Globals;
import org.nervousync.proxy.ProxyConfig;
import org.nervousync.mail.operator.ReceiveOperator;
import org.nervousync.mail.protocol.BaseProtocol;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * <h2 class="en-US">Implements class of JavaMail POP3 protocol</h2>
 * <h2 class="zh-CN">JavaMail的IMAP协议类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 31, 2012 20:08:48 $
 */
public final class POP3Protocol extends BaseProtocol implements ReceiveOperator {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = -8698112033277399242L;

	/**
	 * <h3 class="en-US">Constructor method for POP3Protocol</h3>
	 * <h3 class="zh-CN">POP3Protocol构造方法</h3>
	 *
	 * @param proxyConfig <span class="en-US">Proxy configure information</span>
	 *                    <span class="zh-CN">代理服务器配置信息</span>
	 */
	public POP3Protocol(final ProxyConfig proxyConfig) {
		super(proxyConfig);
		this.hostParam = "mail.pop3.host";
		this.portParam = "mail.pop3.port";
		this.connectionTimeoutParam = "mail.pop3.connectiontimeout";
		this.timeoutParam = "mail.pop3.timeout";
	}

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
	@Override
	public String readUID(Folder folder, Message message) throws MessagingException {
		if (folder instanceof POP3Folder) {
			return ((POP3Folder) folder).getUID(message);
		}
		return Globals.DEFAULT_VALUE_STRING;
	}

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
	@Override
	public Message readMessage(Folder folder, String uid) throws MessagingException {
		if (folder instanceof POP3Folder) {
			for (Message msg : folder.getMessages()) {
				if (((POP3Folder) folder).getUID(msg).equals(uid)) {
					return msg;
				}
			}
		}
		return null;
	}

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
	@Override
	public List<Message> readMessages(Folder folder, String... uidArrays) throws MessagingException {
		List<Message> messageList = new ArrayList<>();
		if (folder instanceof POP3Folder) {
			List<String> uidList = Arrays.asList(uidArrays);
			for (Message message : folder.getMessages()) {
				if (uidList.contains(((POP3Folder) folder).getUID(message))) {
					messageList.add(message);
				}
			}
		}
		return messageList;
	}
}
