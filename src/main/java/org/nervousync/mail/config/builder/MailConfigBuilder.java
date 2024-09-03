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
package org.nervousync.mail.config.builder;

import org.nervousync.mail.config.MailConfig;

/**
 * <h2 class="en-US">Mail configure builder</h2>
 * <h2 class="zh-CN">电子邮件配置信息构造器</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 31, 2022 16:52:27 $
 */
public final class MailConfigBuilder extends AbstractMailConfigBuilder<MailConfig> {
	/**
	 * <h3 class="en-US">Private constructor for MailConfigBuilder</h3>
	 * <h3 class="zh-CN">MailConfigBuilder的私有构造函数</h3>
	 *
	 * @param mailConfig <span class="en-US">Mail configure information</span>
	 *                   <span class="zh-CN">邮件配置信息</span>
	 */
	private MailConfigBuilder(final MailConfig mailConfig) {
		super(mailConfig, mailConfig);
	}

	/**
	 * <h2 class="en-US">Confirm current configure information</h2>
	 * <h2 class="zh-CN">确认当前配置信息</h2>
	 */
	@Override
	protected void build() {
		super.parentBuilder.copyProperties(this.mailConfig);
	}

	/**
	 * <h3 class="en-US">Static method for create MailConfigBuilder instance by new mail configure</h3>
	 * <h3 class="zh-CN">私有方法用于使用新的邮件配置信息创建邮件配置构造器实例对象</h3>
	 *
	 * @return    <span class="en-US">Generated MailConfigBuilder instance</span>
	 * <span class="zh-CN">生成的邮件配置构造器实例对象</span>
	 */
	public static MailConfigBuilder newBuilder() {
		return newBuilder(new MailConfig());
	}

	/**
	 * <h3 class="en-US">Static method for create MailConfigBuilder instance by given mail configure</h3>
	 * <h3 class="zh-CN">私有方法用于使用给定的邮件配置信息创建邮件配置构造器实例对象</h3>
	 *
	 * @param mailConfig <span class="en-US">Mail configure information</span>
	 *                   <span class="zh-CN">邮件配置信息</span>
	 * @return    <span class="en-US">Generated MailConfigBuilder instance</span>
	 * <span class="zh-CN">生成的邮件配置构造器实例对象</span>
	 */
	public static MailConfigBuilder newBuilder(final MailConfig mailConfig) {
		return new MailConfigBuilder(mailConfig);
	}
}
