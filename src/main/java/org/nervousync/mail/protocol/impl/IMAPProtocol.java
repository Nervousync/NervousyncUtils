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
import org.eclipse.angus.mail.imap.IMAPFolder;
import org.nervousync.commons.Globals;
import org.nervousync.proxy.ProxyConfig;
import org.nervousync.mail.operator.ReceiveOperator;
import org.nervousync.mail.operator.SendOperator;
import org.nervousync.mail.protocol.BaseProtocol;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * <h2 class="en-US">Implements class of JavaMail IMAP protocol</h2>
 * <h2 class="zh-CN">JavaMail的IMAP协议类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 31, 2012 19:58:05 $
 */
public final class IMAPProtocol extends BaseProtocol implements SendOperator, ReceiveOperator {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 8284024432628098776L;

	/**
	 * <h3 class="en-US">Constructor method for IMAPProtocol</h3>
	 * <h3 class="zh-CN">IMAPProtocol构造方法</h3>
	 *
	 * @param proxyConfig <span class="en-US">Proxy configure information</span>
	 *                    <span class="zh-CN">代理服务器配置信息</span>
	 */
	public IMAPProtocol(final ProxyConfig proxyConfig) {
		super(proxyConfig);
		this.hostParam = "mail.imap.host";
		this.portParam = "mail.imap.port";
		this.connectionTimeoutParam = "mail.imap.connectiontimeout";
		this.timeoutParam = "mail.imap.timeout";
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
		if (folder instanceof IMAPFolder) {
			return Long.toString(((IMAPFolder) folder).getUID(message));
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
		if (folder instanceof IMAPFolder) {
			return ((IMAPFolder) folder).getMessageByUID(Long.parseLong(uid));
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
		if (folder instanceof IMAPFolder) {
			long[] uidList = new long[uidArrays.length];
			for (int i = 0; i < uidArrays.length; i++) {
				uidList[i] = Long.parseLong(uidArrays[i]);
			}
			Collections.addAll(messageList, ((IMAPFolder) folder).getMessagesByUID(uidList));
		}
		return messageList;
	}
}
