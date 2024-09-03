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
package org.nervousync.mail.authenticator;

import jakarta.mail.Authenticator;
import jakarta.mail.PasswordAuthentication;
import org.nervousync.commons.Globals;
import org.nervousync.utils.StringUtils;

/**
 * <h2 class="en-US">Username and password authenticator for SMTP/POP3/IMAP server</h2>
 * <h2 class="zh-CN">用于SMTP/POP3/IMAP服务器用户名、密码的身份验证器</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 31, 2012 20:56:49 $
 */
public final class DefaultAuthenticator extends Authenticator {
	/**
	 * <span class="en-US">A repository for a user name and a password.</span>
	 * <span class="zh-CN">存储用户名密码的仓库</span>
	 */
	private final PasswordAuthentication passwordAuthentication;

	/**
	 * <h3 class="en-US">Constructor method for DefaultAuthenticator</h3>
	 * <h3 class="zh-CN">DefaultAuthenticator构造方法</h3>
	 *
	 * @param username <span class="en-US">Authenticate username</span>
	 *                 <span class="zh-CN">验证用户名</span>
	 * @param password <span class="en-US">Authenticate password</span>
	 *                 <span class="zh-CN">验证密码</span>
	 */
	public DefaultAuthenticator(String username, String password) {
		this.passwordAuthentication =
				new PasswordAuthentication(StringUtils.notBlank(username) ? username : Globals.DEFAULT_VALUE_STRING,
						StringUtils.notBlank(password) ? password : Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * <h3 class="en-US">Getter method for repository for a user name and a password.</h3>
	 * <h3 class="zh-CN">存储用户名密码的仓库的Getter方法</h3>
	 *
	 * @return <span class="en-US">A repository for a user name and a password.</span>
	 * <span class="zh-CN">存储用户名密码的仓库</span>
	 */
	@Override
	protected PasswordAuthentication getPasswordAuthentication() {
		return this.passwordAuthentication;
	}
}
