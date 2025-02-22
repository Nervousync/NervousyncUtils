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
package org.nervousync.http.header;

/**
 * <h2 class="en-US">Simple Header Define</h2>
 * <h2 class="zh-CN">Cookie信息定义</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jan 4, 2018 12:15:18 $
 */
public final class SimpleHeader {
	/**
	 * <span class="en-US">Header name</span>
	 * <span class="zh-CN">Header名</span>
	 */
	private final String headerName;
	/**
	 * <span class="en-US">Header value</span>
	 * <span class="zh-CN">Header值</span>
	 */
	private final String headerValue;

	/**
	 * <h3 class="en-US">Constructor method for SimpleHeader</h3>
	 * <h3 class="zh-CN">SimpleHeader构造方法</h3>
	 *
	 * @param headerName  <span class="en-US">Header name</span>
	 *                    <span class="zh-CN">Header名</span>
	 * @param headerValue <span class="en-US">Header value</span>
	 *                    <span class="zh-CN">Header值</span>
	 */
	public SimpleHeader(String headerName, String headerValue) {
		this.headerName = headerName;
		this.headerValue = headerValue;
	}

	/**
	 * <h3 class="en-US">Getter method for header name</h3>
	 * <h3 class="zh-CN">Header名的Getter方法</h3>
	 *
	 * @return <span class="en-US">Header name</span>
	 * <span class="zh-CN">Header名</span>
	 */
	public String getHeaderName() {
		return headerName;
	}

	/**
	 * <h3 class="en-US">Getter method for header value</h3>
	 * <h3 class="zh-CN">Header值的Getter方法</h3>
	 *
	 * @return <span class="en-US">Header value</span>
	 * <span class="zh-CN">Header值</span>
	 */
	public String getHeaderValue() {
		return headerValue;
	}
}
