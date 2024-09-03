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
package org.nervousync.beans.servlet.request;

import java.io.File;
import java.io.IOException;
import java.util.*;

import jakarta.annotation.Nonnull;
import org.nervousync.commons.Globals;
import org.nervousync.proxy.AbstractProxyConfigBuilder;
import org.nervousync.enumerations.web.HttpMethodOption;
import org.nervousync.http.cert.TrustCert;
import org.nervousync.http.cookie.CookieEntity;
import org.nervousync.http.header.SimpleHeader;
import org.nervousync.proxy.ProxyConfig;
import org.nervousync.utils.FileUtils;

/**
 * <h2 class="en-US">Request information define</h2>
 * <p class="en-US">Using for parameter of method: org.nervousync.utils.RequestUtils#sendRequest</p>
 * <h2 class="zh-CN">网络请求信息定义</h2>
 * <p class="en-US">用于方法org.nervousync.utils.RequestUtils#sendRequest的参数值</p>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.4 $ $Date: Sep 25, 2022 11:04:17 $
 */
public final class RequestInfo {
	/**
	 * <span class="en-US">Enumeration value of HttpMethodOption</span>
	 * <span class="zh-CN">HttpMethodOption的枚举值</span>
	 *
	 * @see org.nervousync.enumerations.web.HttpMethodOption
	 */
	private final HttpMethodOption methodOption;
	/**
	 * <span class="en-US">Proxy server config for sending request</span>
	 * <p class="en-US">Default is null for direct connect</p>
	 * <span class="zh-CN">发送请求时使用的代理服务器设置</span>
	 * <p class="zh-CN">默认为null代表不使用代理服务器</p>
	 *
	 * @see org.nervousync.proxy.ProxyConfig
	 */
	private final ProxyConfig proxyConfig;
	/**
	 * <span class="en-US">Trusted certificate list for sending secure request</span>
	 * <p class="en-US">Default is empty list for using JDK certificate library</p>
	 * <span class="zh-CN">发送加密请求时信任的证书列表</span>
	 * <p class="en-US">默认为空列表，代表使用JDK默认的证书库</p>
	 *
	 * @see org.nervousync.http.cert.TrustCert
	 */
	private final List<TrustCert> trustTrustCerts;
	/**
	 * <span class="en-US">Pass phrase for system certificate library</span>
	 * <span class="zh-CN">系统信任证书库读取密钥</span>
	 */
	private final String passPhrase;
	/**
	 * <span class="en-US">Using for setting user agent string of request header</span>
	 * <span class="zh-CN">用于设置请求头中的用户代理信息</span>
	 */
	private final String userAgent;
	/**
	 * <span class="en-US">Current request url path</span>
	 * <span class="zh-CN">当前请求地址</span>
	 */
	private final String requestUrl;
	/**
	 * <span class="en-US">Character encoding for http request header "Content-Type" and send request body</span>
	 * <span class="zh-CN">请求头"Content-Type"及发送请求体使用的编码集</span>
	 */
	private final String charset;
	/**
	 * <span class="en-US">String value for http request header "Content-Type"</span>
	 * <span class="zh-CN">请求头"Content-Type"的字符串值</span>
	 */
	private final String contentType;
	/**
	 * <span class="en-US">Request timeout setting</span>
	 * <span class="zh-CN">请求超时时间</span>
	 */
	private final int timeOut;
	/**
	 * <span class="en-US">Binary data array of current request will post</span>
	 * <span class="zh-CN">当前请求要发送的二进制数据数组</span>
	 */
	private final byte[] postData;
	/**
	 * <span class="en-US">Request header information list</span>
	 * <span class="zh-CN">发送请求的请求头信息列表</span>
	 */
	private final List<SimpleHeader> headers;
	/**
	 * <span class="en-US">Request parameters information mapping</span>
	 * <span class="zh-CN">发送请求的参数信息映射</span>
	 */
	private final Map<String, String[]> parameters;
	/**
	 * <span class="en-US">Upload files of request parameters mapping</span>
	 * <span class="zh-CN">发送请求的上传文件参数信息映射</span>
	 */
	private final Map<String, File> uploadParams;
	/**
	 * <span class="en-US">Request cookies information list</span>
	 * <span class="zh-CN">发送请求的Cookie信息列表</span>
	 */
	private final List<CookieEntity> cookieList;

	/**
	 * <h3 class="en-US">Constructor for RequestInfo</h3>
	 * <p class="en-US">Only using for RequestBuilder instance to generate RequestInfo instance</p>
	 * <h3 class="zh-CN">RequestInfo的构造方法</h3>
	 * <p class="zh-CN">仅用于请求构造器生成RequestInfo实例对象使用</p>
	 *
	 * @param methodOption <span class="en-US">Enumeration value of HttpMethodOption</span>
	 *                     <span class="zh-CN">HttpMethodOption的枚举值</span>
	 * @param requestUrl   <span class="en-US">Current request url path</span>
	 *                     <span class="zh-CN">当前请求地址</span>
	 * @param charset      <span class="en-US">Character encoding for http request header "Content-Type" and send request body</span>
	 *                     <span class="zh-CN">请求头"Content-Type"及发送请求体使用的编码集</span>
	 * @param timeOut      <span class="en-US">Request timeout setting</span>
	 *                     <span class="zh-CN">请求超时时间</span>
	 * @param headers      <span class="en-US">Request header information list</span>
	 *                     <span class="zh-CN">发送请求的请求头信息列表</span>
	 * @param parameters   <span class="en-US">Request parameters information mapping</span>
	 *                     <span class="zh-CN">发送请求的参数信息映射</span>
	 * @param uploadParams <span class="en-US">Upload files of request parameters mapping</span>
	 *                     <span class="zh-CN">发送请求的上传文件参数信息映射</span>
	 * @param cookieList   <span class="en-US">Request cookies information list</span>
	 *                     <span class="zh-CN">发送请求的Cookie信息列表</span>
	 */
	private RequestInfo(final HttpMethodOption methodOption, final ProxyConfig proxyConfig,
	                    final List<TrustCert> trustTrustCerts, final String passPhrase, final String userAgent,
	                    final String requestUrl, final String charset, final String contentType, final int timeOut,
	                    final byte[] postData, final List<SimpleHeader> headers, final Map<String, String[]> parameters,
	                    final Map<String, File> uploadParams, final List<CookieEntity> cookieList) {
		this.methodOption = methodOption;
		this.proxyConfig = proxyConfig;
		this.trustTrustCerts = trustTrustCerts;
		this.passPhrase = passPhrase;
		this.userAgent = userAgent;
		this.requestUrl = requestUrl;
		this.charset = charset;
		this.contentType = contentType;
		this.timeOut = timeOut;
		this.postData = postData;
		this.headers = headers;
		this.parameters = parameters;
		this.uploadParams = uploadParams;
		this.cookieList = cookieList;
	}

	/**
	 * Builder request builder.
	 *
	 * @param httpMethodOption the http method option
	 * @return the request builder
	 */
	public static RequestBuilder builder(final HttpMethodOption httpMethodOption) {
		return new RequestBuilder(httpMethodOption);
	}

	/**
	 * <h3 class="en-US">Getter method for method option</h3>
	 * <h3 class="zh-CN">请求类型的Getter方法</h3>
	 */
	public HttpMethodOption getMethodOption() {
		return methodOption;
	}

	/**
	 * <h3 class="en-US">Getter method for upload parameters</h3>
	 * <h3 class="zh-CN">上传文件信息映射的Getter方法</h3>
	 */
	public Map<String, File> getUploadParams() {
		return uploadParams;
	}

	/**
	 * <h3 class="en-US">Getter method for cookies list</h3>
	 * <h3 class="zh-CN">请求发送的Cookie信息列表的Getter方法</h3>
	 */
	public List<CookieEntity> getCookieList() {
		return cookieList;
	}

	/**
	 * <h3 class="en-US">Getter method for proxy config</h3>
	 * <h3 class="zh-CN">代理服务器设置的Getter方法</h3>
	 */
	public ProxyConfig getProxyInfo() {
		return proxyConfig;
	}

	/**
	 * <h3 class="en-US">Getter method for trusted certificate list</h3>
	 * <h3 class="zh-CN">信任证书列表的Getter方法</h3>
	 */
	public List<TrustCert> getTrustCertInfos() {
		return trustTrustCerts;
	}

	/**
	 * <h3 class="en-US">Getter method for pass phrase of system certificate list</h3>
	 * <h3 class="zh-CN">系统信任证书库读取密钥的Getter方法</h3>
	 */
	public String getPassPhrase() {
		return passPhrase;
	}

	/**
	 * <h3 class="en-US">Getter method for user agent string</h3>
	 * <h3 class="zh-CN">用户代理字符串的Getter方法</h3>
	 */
	public String getUserAgent() {
		return userAgent;
	}

	/**
	 * <h3 class="en-US">Getter method for request url</h3>
	 * <h3 class="zh-CN">请求地址的Getter方法</h3>
	 */
	public String getRequestUrl() {
		return requestUrl;
	}

	/**
	 * <h3 class="en-US">Getter method for character encoding</h3>
	 * <h3 class="zh-CN">数据编码集的Getter方法</h3>
	 */
	public String getCharset() {
		return charset;
	}

	/**
	 * <h3 class="en-US">Getter method for content type string</h3>
	 * <h3 class="zh-CN">请求头"Content-Type"字符串的Getter方法</h3>
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * <h3 class="en-US">Getter method for request time out</h3>
	 * <h3 class="zh-CN">请求超时时间的Getter方法</h3>
	 */
	public int getTimeOut() {
		return timeOut;
	}

	/**
	 * <h3 class="en-US">Getter method for post binary data array</h3>
	 * <h3 class="zh-CN">POST发送二进制数据的Getter方法</h3>
	 */
	public byte[] getPostData() {
		return postData;
	}

	/**
	 * <h3 class="en-US">Getter method for request header list</h3>
	 * <h3 class="zh-CN">请求头信息列表的Getter方法</h3>
	 */
	public List<SimpleHeader> getHeaders() {
		return headers;
	}

	/**
	 * <h3 class="en-US">Getter method for parameters mapping</h3>
	 * <h3 class="zh-CN">请求参数信息映射的Getter方法</h3>
	 */
	public Map<String, String[]> getParameters() {
		return parameters;
	}

	/**
	 * <h3 class="en-US">Getter method for upload parameters mapping</h3>
	 * <h3 class="zh-CN">上传文件信息映射的Getter方法</h3>
	 */
	public Map<String, File> getUploadParam() {
		return uploadParams;
	}

	/**
	 * <h2 class="en-US">Request proxy configure builder</h2>
	 * <h2 class="zh-CN">网络请求代理服务器构建器</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0.0 $ $Date: Aug 25, 2017 11:08:22 $
	 */
	public static final class RequestProxyBuilder extends AbstractProxyConfigBuilder<RequestBuilder> {
		/**
		 * <h3 class="en-US">Private constructor for RequestProxyBuilder</h3>
		 * <h3 class="zh-CN">RequestProxyBuilder的私有构造方法</h3>
		 *
		 * @param requestBuilder <span class="en-US">RequestBuilder instance</span>
		 *                       <span class="zh-CN">RequestBuilder实例对象</span>
		 */
		private RequestProxyBuilder(@Nonnull final RequestBuilder requestBuilder) {
			super(requestBuilder, requestBuilder.proxyConfig);
		}

		/**
		 * <h3 class="en-US">Confirm proxy configure</h3>
		 * <h3 class="zh-CN">确认代理服务器配置</h3>
		 */
		@Override
		protected void build() {
			this.parentBuilder.proxyConfig(this.proxyConfig);
		}
	}

	/**
	 * <h2 class="en-US">Request builder</h2>
	 * <h2 class="zh-CN">网络请求构建器</h2>
	 */
	public static final class RequestBuilder {
		/**
		 * <span class="en-US">Enumeration value of HttpMethodOption</span>
		 * <span class="zh-CN">HttpMethodOption的枚举值</span>
		 *
		 * @see org.nervousync.enumerations.web.HttpMethodOption
		 */
		private final HttpMethodOption methodOption;
		/**
		 * <span class="en-US">Proxy server config for sending request</span>
		 * <p class="en-US">Default is null for direct connect</p>
		 * <span class="zh-CN">发送请求时使用的代理服务器设置</span>
		 * <p class="zh-CN">默认为null代表不使用代理服务器</p>
		 *
		 * @see org.nervousync.proxy.ProxyConfig
		 */
		private ProxyConfig proxyConfig;
		/**
		 * <span class="en-US">Trusted certificate list for sending secure request</span>
		 * <p class="en-US">Default is empty list for using JDK certificate library</p>
		 * <span class="zh-CN">发送加密请求时信任的证书列表</span>
		 * <p class="en-US">默认为空列表，代表使用JDK默认的证书库</p>
		 *
		 * @see org.nervousync.http.cert.TrustCert
		 */
		private final List<TrustCert> trustTrustCerts = new ArrayList<>();
		/**
		 * <span class="en-US">Pass phrase for system certificate library</span>
		 * <span class="zh-CN">系统信任证书库读取密钥</span>
		 */
		private String passPhrase;
		/**
		 * <span class="en-US">Using for setting user agent string of request header</span>
		 * <span class="zh-CN">用于设置请求头中的用户代理信息</span>
		 */
		private String userAgent;
		/**
		 * <span class="en-US">Current request url path</span>
		 * <span class="zh-CN">当前请求地址</span>
		 */
		private String requestUrl;
		/**
		 * <span class="en-US">Character encoding for http request header "Content-Type" and send request body</span>
		 * <span class="zh-CN">请求头"Content-Type"及发送请求体使用的编码集</span>
		 */
		private String charset;
		/**
		 * <span class="en-US">String value for http request header "Content-Type"</span>
		 * <span class="zh-CN">请求头"Content-Type"的字符串值</span>
		 */
		private String contentType;
		/**
		 * <span class="en-US">Request timeout setting</span>
		 * <span class="zh-CN">请求超时时间</span>
		 */
		private int timeOut = Globals.DEFAULT_TIME_OUT;
		/**
		 * <span class="en-US">Binary data array of current request will post</span>
		 * <span class="zh-CN">当前请求要发送的二进制数据数组</span>
		 */
		private byte[] postData;
		/**
		 * <span class="en-US">Request header information list</span>
		 * <span class="zh-CN">发送请求的请求头信息列表</span>
		 */
		private final List<SimpleHeader> headers = new ArrayList<>();
		/**
		 * <span class="en-US">Request parameters information mapping</span>
		 * <span class="zh-CN">发送请求的参数信息映射</span>
		 */
		private final Map<String, String[]> parameters = new HashMap<>();
		/**
		 * <span class="en-US">Upload files of request parameters mapping</span>
		 * <span class="zh-CN">发送请求的上传文件参数信息映射</span>
		 */
		private final Map<String, File> uploadParams = new HashMap<>();
		/**
		 * <span class="en-US">Request cookies information list</span>
		 * <span class="zh-CN">发送请求的Cookie信息列表</span>
		 */
		private final List<CookieEntity> cookieList = new ArrayList<>();

		private RequestBuilder(final HttpMethodOption methodOption) {
			this.methodOption = methodOption;
		}

		/**
		 * <h3 class="en-US">Confirm request info and generate RequestInfo instance</h3>
		 * <h3 class="zh-CN">确认请求配置信息并生成RequestInfo实例对象</h3>
		 *
		 * @return <span class="en-US">RequestInfo instance</span>
		 * <span class="zh-CN">RequestInfo实例对象</span>
		 */
		public RequestInfo build() {
			return new RequestInfo(this.methodOption, this.proxyConfig, this.trustTrustCerts, this.passPhrase,
					this.userAgent, this.requestUrl, this.charset, this.contentType, this.timeOut,
					this.postData, this.headers, this.parameters, this.uploadParams, this.cookieList);
		}

		/**
		 * <h3 class="en-US">Generate RequestProxyBuilder instance to configure proxy server</h3>
		 * <h3 class="zh-CN">生成RequestProxyBuilder实例对象用于配置代理服务器</h3>
		 *
		 * @return <span class="en-US">RequestProxyBuilder instance</span>
		 * <span class="zh-CN">RequestProxyBuilder实例对象</span>
		 */
		public RequestProxyBuilder proxyConfig() {
			return new RequestProxyBuilder(this);
		}

		/**
		 * <h3 class="en-US">Add trusted certificate library</h3>
		 * <h3 class="zh-CN">添加信任证书库</h3>
		 *
		 * @param certPath     <span class="en-US">Trust certificate path</span>
		 *                     <span class="zh-CN">信任证书地址</span>
		 * @param certPassword <span class="en-US">Password of trust certificate</span>
		 *                     <span class="zh-CN">读取证书的密钥</span>
		 * @return <span class="en-US">Current RequestBuilder instance</span>
		 * <span class="zh-CN">当前RequestBuilder实例对象</span>
		 */
		public RequestBuilder addTrustCertificate(final String certPath, final String certPassword) {
			try {
				return this.addTrustCertificate(FileUtils.readFileBytes(certPath), certPassword);
			} catch (IOException ignore) {
			}
			return this;
		}

		/**
		 * <h3 class="en-US">Add trusted certificate library</h3>
		 * <h3 class="zh-CN">添加信任证书库</h3>
		 *
		 * @param certContent  <span class="en-US">Trust certificate data bytes</span>
		 *                     <span class="zh-CN">信任证书二进制字节数组</span>
		 * @param certPassword <span class="en-US">Password of trust certificate</span>
		 *                     <span class="zh-CN">读取证书的密钥</span>
		 * @return <span class="en-US">Current RequestBuilder instance</span>
		 * <span class="zh-CN">当前RequestBuilder实例对象</span>
		 */
		public RequestBuilder addTrustCertificate(final byte[] certContent, final String certPassword) {
			Optional.of(TrustCert.newInstance(certContent, certPassword))
					.filter(trustCert ->
							this.trustTrustCerts.stream().noneMatch(existCert ->
									existCert.getSha256().equals(trustCert.getSha256())))
					.ifPresent(this.trustTrustCerts::add);
			return this;
		}

		/**
		 * <h3 class="en-US">Configure pass phrase of system certificate library</h3>
		 * <h3 class="zh-CN">设置系统证书库的读取密码</h3>
		 *
		 * @param passPhrase <span class="en-US">Pass phrase of system certificate library</span>
		 *                   <span class="zh-CN">系统证书库的读取密码</span>
		 * @return <span class="en-US">Current RequestBuilder instance</span>
		 * <span class="zh-CN">当前RequestBuilder实例对象</span>
		 */
		public RequestBuilder passPhrase(final String passPhrase) {
			this.passPhrase = passPhrase;
			return this;
		}

		/**
		 * <h3 class="en-US">Configure user agent string will used</h3>
		 * <h3 class="zh-CN">设置即将使用的用户代理字符串</h3>
		 *
		 * @param userAgent <span class="en-US">User agent string</span>
		 *                  <span class="zh-CN">用户代理字符串</span>
		 * @return <span class="en-US">Current RequestBuilder instance</span>
		 * <span class="zh-CN">当前RequestBuilder实例对象</span>
		 */
		public RequestBuilder userAgent(final String userAgent) {
			this.userAgent = userAgent;
			return this;
		}

		/**
		 * <h3 class="en-US">Configure request url</h3>
		 * <h3 class="zh-CN">设置请求地址</h3>
		 *
		 * @param requestUrl <span class="en-US">Request url string</span>
		 *                   <span class="zh-CN">请求地址字符串</span>
		 * @return <span class="en-US">Current RequestBuilder instance</span>
		 * <span class="zh-CN">当前RequestBuilder实例对象</span>
		 */
		public RequestBuilder requestUrl(final String requestUrl) {
			this.requestUrl = requestUrl;
			return this;
		}

		/**
		 * <h3 class="en-US">Configure character encoding</h3>
		 * <h3 class="zh-CN">设置请求字符集</h3>
		 *
		 * @param charset <span class="en-US">character encoding</span>
		 *                <span class="zh-CN">字符集</span>
		 * @return <span class="en-US">Current RequestBuilder instance</span>
		 * <span class="zh-CN">当前RequestBuilder实例对象</span>
		 */
		public RequestBuilder charset(final String charset) {
			this.charset = charset;
			return this;
		}

		/**
		 * <h3 class="en-US">Configure content type string</h3>
		 * <h3 class="zh-CN">设置"Content-Type"值</h3>
		 *
		 * @param contentType <span class="en-US">Content type string</span>
		 *                    <span class="zh-CN">需要设置的字符串</span>
		 * @return <span class="en-US">Current RequestBuilder instance</span>
		 * <span class="zh-CN">当前RequestBuilder实例对象</span>
		 */
		public RequestBuilder contentType(final String contentType) {
			this.contentType = contentType;
			return this;
		}

		/**
		 * <h3 class="en-US">Configure request timeout</h3>
		 * <h3 class="zh-CN">设置请求超时时间</h3>
		 *
		 * @param timeOut <span class="en-US">Timeout value</span>
		 *                <span class="zh-CN">请求超时时间</span>
		 * @return <span class="en-US">Current RequestBuilder instance</span>
		 * <span class="zh-CN">当前RequestBuilder实例对象</span>
		 */
		public RequestBuilder timeOut(final int timeOut) {
			this.timeOut = timeOut;
			return this;
		}

		/**
		 * <h3 class="en-US">Configure request send data bytes</h3>
		 * <h3 class="zh-CN">设置请求发送的二进制数据</h3>
		 *
		 * @param postData <span class="en-US">Binary data bytes</span>
		 *                 <span class="zh-CN">二进制数据</span>
		 * @return <span class="en-US">Current RequestBuilder instance</span>
		 * <span class="zh-CN">当前RequestBuilder实例对象</span>
		 */
		public RequestBuilder postData(final byte[] postData) {
			this.postData = postData;
			return this;
		}

		/**
		 * <h3 class="en-US">Add request header name and value</h3>
		 * <h3 class="zh-CN">添加请求头的键和值</h3>
		 *
		 * @param headerName  <span class="en-US">Request header name</span>
		 *                    <span class="zh-CN">请求头键名</span>
		 * @param headerValue <span class="en-US">Request header value</span>
		 *                    <span class="zh-CN">请求头键值</span>
		 * @return <span class="en-US">Current RequestBuilder instance</span>
		 * <span class="zh-CN">当前RequestBuilder实例对象</span>
		 */
		public RequestBuilder addHeader(final String headerName, final String headerValue) {
			this.headers.add(new SimpleHeader(headerName, headerValue));
			return this;
		}

		/**
		 * <h3 class="en-US">Add request parameter name and value</h3>
		 * <h3 class="zh-CN">添加请求参数的键和值</h3>
		 *
		 * @param parameterName   <span class="en-US">Request parameter name</span>
		 *                        <span class="zh-CN">请求参数名</span>
		 * @param parameterValues <span class="en-US">Request parameter value</span>
		 *                        <span class="zh-CN">请求参数值</span>
		 * @return <span class="en-US">Current RequestBuilder instance</span>
		 * <span class="zh-CN">当前RequestBuilder实例对象</span>
		 */
		public RequestBuilder addParameter(final String parameterName, final String[] parameterValues) {
			this.parameters.put(parameterName, parameterValues);
			return this;
		}

		/**
		 * <h3 class="en-US">Add request upload parameter name and value</h3>
		 * <h3 class="zh-CN">添加请求上传数据的键和值</h3>
		 *
		 * @param parameterName  <span class="en-US">Request upload parameter name</span>
		 *                       <span class="zh-CN">请求上传参数名</span>
		 * @param parameterValue <span class="en-US">Request upload parameter value</span>
		 *                       <span class="zh-CN">请求上传文件实例对象</span>
		 * @return <span class="en-US">Current RequestBuilder instance</span>
		 * <span class="zh-CN">当前RequestBuilder实例对象</span>
		 */
		public RequestBuilder addUploadParam(final String parameterName, final File parameterValue) {
			this.uploadParams.put(parameterName, parameterValue);
			return this;
		}

		/**
		 * <h3 class="en-US">Add request cookie values</h3>
		 * <h3 class="zh-CN">添加请求Cookie信息</h3>
		 *
		 * @param cookieEntities <span class="en-US">CookieEntity instance array</span>
		 *                       <span class="zh-CN">CookieEntity实例对象数组</span>
		 * @return <span class="en-US">Current RequestBuilder instance</span>
		 * <span class="zh-CN">当前RequestBuilder实例对象</span>
		 * @see org.nervousync.http.cookie.CookieEntity
		 */
		public RequestBuilder addCookies(final CookieEntity... cookieEntities) {
			this.cookieList.addAll(Arrays.asList(cookieEntities));
			return this;
		}

		/**
		 * <h3 class="en-US">Add request cookie values from response header "Set-Cookie"</h3>
		 * <h3 class="zh-CN">解析响应数据头中的"Set-Cookie"信息，并添加请求Cookie信息</h3>
		 *
		 * @param responseCookieValue <span class="en-US">String value of response header "Set-Cookie"</span>
		 *                            <span class="zh-CN">响应头中的"Set-Cookie"字符串值</span>
		 * @return <span class="en-US">Current RequestBuilder instance</span>
		 * <span class="zh-CN">当前RequestBuilder实例对象</span>
		 */
		public RequestBuilder addCookies(final String responseCookieValue) {
			this.cookieList.add(new CookieEntity(responseCookieValue));
			return this;
		}

		/**
		 * <h3 class="en-US">Confirm proxy configure</h3>
		 * <h3 class="zh-CN">确认代理服务器配置</h3>
		 *
		 * @param proxyConfig <span class="en-US">ProxyConfig instance</span>
		 *                    <span class="zh-CN">ProxyConfig实例对象</span>
		 * @see org.nervousync.proxy.ProxyConfig
		 */
		void proxyConfig(final ProxyConfig proxyConfig) {
			this.proxyConfig = proxyConfig;
		}
	}
}
