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
package org.nervousync.mail;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import org.nervousync.commons.Globals;

/**
 * <h2 class="en-US">E-Mail Information Define</h2>
 * <h2 class="zh-CN">电子邮件信息定义</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 31, 2012 19:03:47 $
 */
public final class MailObject implements Serializable {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = -4277408041510934598L;
	/**
	 * <span class="en-US">Unified identified ID</span>
	 * <span class="zh-CN">统一识别代码</span>
	 */
	private String uid;
	/**
	 * <span class="en-US">Mail subject information</span>
	 * <span class="zh-CN">邮件标题信息</span>
	 */
	private String subject;
	/**
	 * <span class="en-US">Mail content information</span>
	 * <span class="zh-CN">邮件正文信息</span>
	 */
	private String content;
	/**
	 * <span class="en-US">Mail charset encoding</span>
	 * <span class="zh-CN">邮件字符集编码</span>
	 */
	private String charset = Globals.DEFAULT_ENCODING;
	/**
	 * <span class="en-US">Mail content type information</span>
	 * <span class="zh-CN">邮件正文数据类型</span>
	 */
	private String contentType = Globals.DEFAULT_CONTENT_TYPE_TEXT;
	/**
	 * <span class="en-US">Mail send address</span>
	 * <span class="zh-CN">邮件发送地址</span>
	 */
	private String sendAddress;
	/**
	 * <span class="en-US">Mail reply address</span>
	 * <span class="zh-CN">邮件回复地址</span>
	 */
	private List<String> replyAddress;
	/**
	 * <span class="en-US">Mail send datetime</span>
	 * <span class="zh-CN">邮件发送时间</span>
	 */
	private Date sendDate;
	/**
	 * <span class="en-US">Mail receive address list</span>
	 * <span class="zh-CN">邮件收件地址列表</span>
	 */
	private List<String> receiveAddress;
	/**
	 * <span class="en-US">Mail carbon copy address list</span>
	 * <span class="zh-CN">邮件抄送地址列表</span>
	 */
	private List<String> ccAddress;
	/**
	 * <span class="en-US">Mail blind carbon copy address list</span>
	 * <span class="zh-CN">邮件暗抄送地址列表</span>
	 */
	private List<String> bccAddress;
	/**
	 * <span class="en-US">Mail attachment file list</span>
	 * <span class="zh-CN">邮件附件文件列表</span>
	 */
	private List<String> attachFiles;
	/**
	 * <span class="en-US">Mail include file list</span>
	 * <span class="zh-CN">邮件包含文件列表</span>
	 */
	private List<String> includeFiles;

	/**
	 * <h3 class="en-US">Getter method for unified identified ID</h3>
	 * <h3 class="zh-CN">统一识别代码的Getter方法</h3>
	 *
	 * <span class="en-US">Unified identified ID</span>
	 * <span class="zh-CN">统一识别代码</span>
	 */
	public String getUid() {
		return uid;
	}

	/**
	 * <h3 class="en-US">Setter method for unified identified ID</h3>
	 * <h3 class="zh-CN">统一识别代码的Setter方法</h3>
	 *
	 * @param uid <span class="en-US">Unified identified ID</span>
	 *            <span class="zh-CN">统一识别代码</span>
	 */
	public void setUid(String uid) {
		this.uid = uid;
	}

	/**
	 * <h3 class="en-US">Getter method for mail subject information</h3>
	 * <h3 class="zh-CN">邮件标题信息的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail subject information</span>
	 * <span class="zh-CN">邮件标题信息</span>
	 */
	public String getSubject() {
		return subject;
	}

	/**
	 * <h3 class="en-US">Setter method for mail subject information</h3>
	 * <h3 class="zh-CN">邮件标题信息的Setter方法</h3>
	 *
	 * @param subject <span class="en-US">Mail subject information</span>
	 *                <span class="zh-CN">邮件标题信息</span>
	 */
	public void setSubject(String subject) {
		this.subject = subject;
	}

	/**
	 * <h3 class="en-US">Getter method for mail content information</h3>
	 * <h3 class="zh-CN">邮件正文信息的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail content information</span>
	 * <span class="zh-CN">邮件正文信息</span>
	 */
	public String getContent() {
		return content;
	}

	/**
	 * <h3 class="en-US">Setter method for mail content information</h3>
	 * <h3 class="zh-CN">邮件正文信息的Setter方法</h3>
	 *
	 * @param content <span class="en-US">Mail content information</span>
	 *                <span class="zh-CN">邮件正文信息</span>
	 */
	public void setContent(String content) {
		this.content = content;
	}

	/**
	 * <h3 class="en-US">Getter method for mail charset encoding</h3>
	 * <h3 class="zh-CN">邮件字符集编码的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail charset encoding</span>
	 * <span class="zh-CN">邮件字符集编码</span>
	 */
	public String getCharset() {
		return charset;
	}

	/**
	 * <h3 class="en-US">Setter method for mail charset encoding</h3>
	 * <h3 class="zh-CN">邮件字符集编码的Setter方法</h3>
	 *
	 * @param charset <span class="en-US">Mail charset encoding</span>
	 *                <span class="zh-CN">邮件字符集编码</span>
	 */
	public void setCharset(String charset) {
		this.charset = charset;
	}

	/**
	 * <h3 class="en-US">Getter method for mail content type information</h3>
	 * <h3 class="zh-CN">邮件正文数据类型的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail content type information</span>
	 * <span class="zh-CN">邮件正文数据类型</span>
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * <h3 class="en-US">Setter method for mail content type information</h3>
	 * <h3 class="zh-CN">邮件正文数据类型的Setter方法</h3>
	 *
	 * @param contentType <span class="en-US">Mail content type information</span>
	 *                    <span class="zh-CN">邮件正文数据类型</span>
	 */
	public void setContentType(String contentType) {
		this.contentType = contentType;
	}

	/**
	 * <h3 class="en-US">Getter method for mail send address</h3>
	 * <h3 class="zh-CN">邮件发送地址的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail send address</span>
	 * <span class="zh-CN">邮件发送地址</span>
	 */
	public String getSendAddress() {
		return sendAddress;
	}

	/**
	 * <h3 class="en-US">Setter method for mail send address</h3>
	 * <h3 class="zh-CN">邮件发送地址的Setter方法</h3>
	 *
	 * @param sendAddress <span class="en-US">Mail send address</span>
	 *                    <span class="zh-CN">邮件发送地址</span>
	 */
	public void setSendAddress(String sendAddress) {
		this.sendAddress = sendAddress;
	}

	/**
	 * <h3 class="en-US">Getter method for mail reply address</h3>
	 * <h3 class="zh-CN">邮件回复地址的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail reply address</span>
	 * <span class="zh-CN">邮件回复地址</span>
	 */
	public List<String> getReplyAddress() {
		return replyAddress;
	}

	/**
	 * <h3 class="en-US">Setter method for mail reply address</h3>
	 * <h3 class="zh-CN">邮件回复地址的Setter方法</h3>
	 *
	 * @param replyAddress <span class="en-US">Mail reply address</span>
	 *                     <span class="zh-CN">邮件回复地址</span>
	 */
	public void setReplyAddress(List<String> replyAddress) {
		this.replyAddress = replyAddress;
	}

	/**
	 * <h3 class="en-US">Getter method for mail send datetime</h3>
	 * <h3 class="zh-CN">邮件发送时间的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail send datetime</span>
	 * <span class="zh-CN">邮件发送时间</span>
	 */
	public Date getSendDate() {
		return sendDate == null ? null : (Date) sendDate.clone();
	}

	/**
	 * <h3 class="en-US">Setter method for mail send datetime</h3>
	 * <h3 class="zh-CN">邮件发送时间的Setter方法</h3>
	 *
	 * @param sendDate <span class="en-US">Mail send datetime</span>
	 *                 <span class="zh-CN">邮件发送时间</span>
	 */
	public void setSendDate(Date sendDate) {
		this.sendDate = sendDate == null ? null : (Date) sendDate.clone();
	}

	/**
	 * <h3 class="en-US">Getter method for mail receive address list</h3>
	 * <h3 class="zh-CN">邮件收件地址列表的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail receive address list</span>
	 * <span class="zh-CN">邮件收件地址列表</span>
	 */
	public List<String> getReceiveAddress() {
		return receiveAddress;
	}

	/**
	 * <h3 class="en-US">Setter method for mail receive address list</h3>
	 * <h3 class="zh-CN">邮件收件地址列表的Setter方法</h3>
	 *
	 * @param receiveAddress <span class="en-US">Mail receive address list</span>
	 *                       <span class="zh-CN">邮件收件地址列表</span>
	 */
	public void setReceiveAddress(List<String> receiveAddress) {
		this.receiveAddress = receiveAddress;
	}

	/**
	 * <h3 class="en-US">Getter method for mail carbon copy address list</h3>
	 * <h3 class="zh-CN">邮件抄送地址列表的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail carbon copy address list</span>
	 * <span class="zh-CN">邮件抄送地址列表</span>
	 */
	public List<String> getCcAddress() {
		return ccAddress;
	}

	/**
	 * <h3 class="en-US">Setter method for mail carbon copy address list</h3>
	 * <h3 class="zh-CN">邮件抄送地址列表的Setter方法</h3>
	 *
	 * @param ccAddress <span class="en-US">Mail carbon copy address list</span>
	 *                  <span class="zh-CN">邮件抄送地址列表</span>
	 */
	public void setCcAddress(List<String> ccAddress) {
		this.ccAddress = ccAddress;
	}

	/**
	 * <h3 class="en-US">Getter method for mail blind carbon copy address list</h3>
	 * <h3 class="zh-CN">邮件暗抄送地址列表的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail blind carbon copy address list</span>
	 * <span class="zh-CN">邮件暗抄送地址列表</span>
	 */
	public List<String> getBccAddress() {
		return bccAddress;
	}

	/**
	 * <h3 class="en-US">Setter method for mail blind carbon copy address list</h3>
	 * <h3 class="zh-CN">邮件暗抄送地址列表的Setter方法</h3>
	 *
	 * @param bccAddress <span class="en-US">Mail blind carbon copy address list</span>
	 *                   <span class="zh-CN">邮件暗抄送地址列表</span>
	 */
	public void setBccAddress(List<String> bccAddress) {
		this.bccAddress = bccAddress;
	}

	/**
	 * <h3 class="en-US">Getter method for mail attachment file list</h3>
	 * <h3 class="zh-CN">邮件附件文件列表的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail attachment file list</span>
	 * <span class="zh-CN">邮件附件文件列表</span>
	 */
	public List<String> getAttachFiles() {
		return attachFiles;
	}

	/**
	 * <h3 class="en-US">Setter method for unified identified ID</h3>
	 * <h3 class="zh-CN">邮件附件文件列表的Setter方法</h3>
	 *
	 * @param attachFiles <span class="en-US">Mail attachment file list</span>
	 *                    <span class="zh-CN">邮件附件文件列表</span>
	 */
	public void setAttachFiles(List<String> attachFiles) {
		this.attachFiles = attachFiles;
	}

	/**
	 * <h3 class="en-US">Getter method for mail include file list</h3>
	 * <h3 class="zh-CN">邮件包含文件列表的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mail include file list</span>
	 * <span class="zh-CN">邮件包含文件列表</span>
	 */
	public List<String> getIncludeFiles() {
		return includeFiles;
	}

	/**
	 * <h3 class="en-US">Setter method for mail include file list</h3>
	 * <h3 class="zh-CN">邮件包含文件列表的Setter方法</h3>
	 *
	 * @param includeFiles <span class="en-US">Mail include file list</span>
	 *                     <span class="zh-CN">邮件包含文件列表</span>
	 */
	public void setIncludeFiles(List<String> includeFiles) {
		this.includeFiles = includeFiles;
	}
}
