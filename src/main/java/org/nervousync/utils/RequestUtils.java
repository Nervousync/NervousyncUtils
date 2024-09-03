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
package org.nervousync.utils;

import jakarta.annotation.Nonnull;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.ws.rs.*;
import org.nervousync.beans.servlet.request.RequestAttribute;
import org.nervousync.beans.servlet.request.RequestInfo;
import org.nervousync.beans.servlet.response.ResponseInfo;
import org.nervousync.commons.Globals;
import org.nervousync.enumerations.web.HttpMethodOption;
import org.nervousync.http.cookie.CookieEntity;
import org.nervousync.http.entity.HttpEntity;
import org.nervousync.http.security.GeneX509TrustManager;
import org.nervousync.proxy.ProxyConfig;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.*;
import java.lang.reflect.Method;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.security.cert.*;
import java.time.Duration;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Supplier;

/**
 * <h2 class="en-US">Http Request utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Parse http method string to HttpMethodOption</ul>
 *     <ul>Resolve domain name to IP address</ul>
 *     <ul>Retrieve and verify SSL certificate from server</ul>
 *     <ul>Send request and parse response content to target JavaBean or string</ul>
 *     <ul>Convert data between query string and parameter map</ul>
 *     <ul>Check user role code using <code>request.isUserInRole</code></ul>
 * </span>
 * <h2 class="zh-CN">HTTP请求工具集</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>解析HTTP方法字符串为HttpMethodOption</ul>
 *     <ul>解析域名信息为IP地址</ul>
 *     <ul>读取和验证服务器的SSL证书</ul>
 *     <ul>发送请求并解析响应数据为字符串或指定的JavaBean</ul>
 *     <ul>自由转换查询字符串和参数映射表</ul>
 *     <ul>检查用户的角色信息，使用<code>request.isUserInRole</code>实现</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.4 $ $Date: May 13, 2014 15:36:52 $
 */
public final class RequestUtils {
	/**
	 * <span class="en-US">HTTP Method: GET</span>
	 * <span class="zh-CN">HTTP请求方法：GET</span>
	 */
	public static final String HTTP_METHOD_GET = "GET";
	/**
	 * <span class="en-US">HTTP Method: POST</span>
	 * <span class="zh-CN">HTTP请求方法：POST</span>
	 */
	public static final String HTTP_METHOD_POST = "POST";
	/**
	 * <span class="en-US">HTTP Method: PUT</span>
	 * <span class="zh-CN">HTTP请求方法：PUT</span>
	 */
	public static final String HTTP_METHOD_PUT = "PUT";
	/**
	 * <span class="en-US">HTTP Method: TRACE</span>
	 * <span class="zh-CN">HTTP请求方法：TRACE</span>
	 */
	public static final String HTTP_METHOD_TRACE = "TRACE";
	/**
	 * <span class="en-US">HTTP Method: HEAD</span>
	 * <span class="zh-CN">HTTP请求方法：HEAD</span>
	 */
	public static final String HTTP_METHOD_HEAD = "HEAD";
	/**
	 * <span class="en-US">HTTP Method: DELETE</span>
	 * <span class="zh-CN">HTTP请求方法：DELETE</span>
	 */
	public static final String HTTP_METHOD_DELETE = "DELETE";
	/**
	 * <span class="en-US">HTTP Method: OPTIONS</span>
	 * <span class="zh-CN">HTTP请求方法：OPTIONS</span>
	 */
	public static final String HTTP_METHOD_OPTIONS = "OPTIONS";
	/**
	 * <span class="en-US">Multilingual supported logger instance</span>
	 * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(RequestUtils.class);
	/**
	 * <span class="en-US">Attribute name for HTTP-to-HTTPS redirect</span>
	 * <span class="zh-CN">HTTP-to-HTTPS跳转的属性名</span>
	 */
	private static final String STOWED_REQUEST_ATTRIBS = "ssl.redirect.attrib.stowed";

	/**
	 * <h3 class="en-US">Private constructor for RequestUtils</h3>
	 * <h3 class="zh-CN">Http请求工具集的私有构造方法</h3>
	 */
	private RequestUtils() {
	}

	/**
	 * <h3 class="en-US">Parse HTTP method string to HTTP method option Enumerations</h3>
	 * <h3 class="zh-CN">解析HTTP请求方法字符串为HTTP请求方法枚举</h3>
	 *
	 * @param method <span class="en-US">HTTP method string</span>
	 *               <span class="zh-CN">HTTP请求方法字符串</span>
	 * @return <span class="en-US">HTTP method option Enumerations</span>
	 * <span class="zh-CN">HTTP请求方法枚举</span>
	 */
	public static HttpMethodOption httpMethodOption(final String method) {
		if (StringUtils.isEmpty(method)) {
			return HttpMethodOption.UNKNOWN;
		}

		switch (method.toUpperCase()) {
			case HTTP_METHOD_GET:
				return HttpMethodOption.GET;
			case HTTP_METHOD_HEAD:
				return HttpMethodOption.HEAD;
			case HTTP_METHOD_PUT:
				return HttpMethodOption.PUT;
			case HTTP_METHOD_POST:
				return HttpMethodOption.POST;
			case HTTP_METHOD_TRACE:
				return HttpMethodOption.TRACE;
			case HTTP_METHOD_DELETE:
				return HttpMethodOption.DELETE;
			case HTTP_METHOD_OPTIONS:
				return HttpMethodOption.OPTIONS;
			default:
				return HttpMethodOption.UNKNOWN;
		}
	}

	/**
	 * <h3 class="en-US">Parse method annotation to HTTP method option Enumerations</h3>
	 * <h3 class="zh-CN">解析方法上的注解为HTTP请求方法枚举</h3>
	 *
	 * @param method <span class="en-US">method instance</span>
	 *               <span class="zh-CN">方法实例对象</span>
	 * @return <span class="en-US">HTTP method option Enumerations</span>
	 * <span class="zh-CN">HTTP请求方法枚举</span>
	 */
	public static HttpMethodOption httpMethodOption(final Method method) {
		if (method == null) {
			return HttpMethodOption.UNKNOWN;
		}
		if (method.isAnnotationPresent(GET.class)) {
			return HttpMethodOption.GET;
		}
		if (method.isAnnotationPresent(HEAD.class)) {
			return HttpMethodOption.HEAD;
		}
		if (method.isAnnotationPresent(PUT.class)) {
			return HttpMethodOption.PUT;
		}
		if (method.isAnnotationPresent(POST.class)) {
			return HttpMethodOption.POST;
		}
		if (method.isAnnotationPresent(DELETE.class)) {
			return HttpMethodOption.DELETE;
		}
		if (method.isAnnotationPresent(PATCH.class)) {
			return HttpMethodOption.PATCH;
		}
		return HttpMethodOption.UNKNOWN;
	}

	/**
	 * <h3 class="en-US">Resolve given domain name and return ip address string</h3>
	 * <h3 class="zh-CN">解析给定的域名并返回IP地址字符串</h3>
	 *
	 * @param domainName <span class="en-US">Will resolve for Domain name</span>
	 *                   <span class="zh-CN">将要解析的域名</span>
	 * @return <span class="en-US">All IP address string, concat using character ","</span>
	 * <span class="zh-CN">所有IP地址字符串，使用字符","连接</span>
	 */
	public static String resolveDomain(final String domainName) {
		try {
			InetAddress[] inetAddresses = InetAddress.getAllByName(domainName);
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Resolve domain {} receive address count {}", domainName, inetAddresses.length);
			}
			StringBuilder stringBuilder = new StringBuilder();
			List.of(InetAddress.getAllByName(domainName))
					.forEach(inetAddress -> stringBuilder.append(",").append(inetAddress.getHostAddress()));
			return stringBuilder.substring(1);
		} catch (UnknownHostException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Domain_Resolve_Request_Debug", e, domainName);
			}
		}
		return Globals.DEFAULT_VALUE_STRING;
	}

	private static String domainName(final String urlAddress) {
		if (StringUtils.notBlank(urlAddress)) {
			int beginIndex, endIndex;
			if (urlAddress.toLowerCase().startsWith(Globals.SECURE_HTTP_PROTOCOL)) {
				beginIndex = Globals.SECURE_HTTP_PROTOCOL.length();
			} else if (urlAddress.toLowerCase().startsWith(Globals.HTTP_PROTOCOL)) {
				beginIndex = Globals.HTTP_PROTOCOL.length();
			} else {
				beginIndex = Globals.INITIALIZE_INT_VALUE;
			}
			endIndex = urlAddress.indexOf("/", beginIndex);
			if (endIndex < 0) {
				endIndex = urlAddress.length();
			}
			return urlAddress.substring(beginIndex, endIndex);
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Read server certificate by given url address</h3>
	 * <h3 class="zh-CN">根据给定的url地址获取服务器证书</h3>
	 *
	 * @param urlAddress <span class="en-US">url address</span>
	 *                   <span class="zh-CN">url地址</span>
	 * @return <span class="en-US">Read x509 certificate, if an error occurs return <code>null</code></span>
	 * <span class="zh-CN">读取的x509证书，如果出现异常则返回<code>null</code></span>
	 */
	public static Certificate serverCertificate(final String urlAddress) {
		return Optional.ofNullable(domainName(urlAddress))
				.map(domainName -> {
					try {
						HttpsURLConnection httpsURLConnection = (HttpsURLConnection) new URL(urlAddress).openConnection();
						httpsURLConnection.connect();
						return Arrays.stream(httpsURLConnection.getServerCertificates())
								.filter(serverCertificate ->
										CertificateUtils.matchDomain((X509Certificate) serverCertificate, domainName))
								.findFirst()
								.orElse(null);
					} catch (IOException e) {
						LOGGER.error("Read_Server_Certificate_Request_Error");
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Stack_Message_Error", e);
						}
					}
					return null;
				})
				.orElse(null);
	}

	/**
	 * <h3 class="en-US">Read content length from given request url address</h3>
	 * <h3 class="zh-CN">从给定的URL请求地址获取响应数据长度</h3>
	 *
	 * @param requestUrl <span class="en-US">Request url address</span>
	 *                   <span class="zh-CN">URL请求地址</span>
	 * @return <span class="en-US">content length, or -1 if an error occurs when send request</span>
	 * <span class="zh-CN">响应数据长度，如果请求失败则返回-1</span>
	 */
	public static int contentLength(final String requestUrl) {
		RequestInfo requestInfo = RequestInfo.builder(HttpMethodOption.GET).requestUrl(requestUrl).build();
		return Optional.ofNullable(sendRequest(requestInfo, ResponseInfo.class))
				.filter(responseInfo -> responseInfo.getStatusCode() == HttpURLConnection.HTTP_OK)
				.map(ResponseInfo::getContentLength)
				.orElse(Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * <h3 class="en-US">Send request and parse response data to given target class instance</h3>
	 * <h3 class="zh-CN">发送请求并解析返回数据为给定的目标类型</h3>
	 *
	 * @param <T>         <span class="en-US">target type class</span>
	 *                    <span class="zh-CN">目标类型</span>
	 * @param requestInfo <span class="en-US">Request info</span>
	 *                    <span class="zh-CN">请求信息</span>
	 * @param targetClass <span class="en-US">target type class</span>
	 *                    <span class="zh-CN">目标类型</span>
	 * @return <span class="en-US">Parsed target type class instance or <code>null</code> if an error occurs</span>
	 * <span class="zh-CN">解析的目标类型实例对象，如果请求失败则返回<code>null</code></span>
	 */
	public static <T> T sendRequest(final RequestInfo requestInfo, final Class<T> targetClass) {
		HttpRequest.Builder requestBuilder = HttpRequest.newBuilder();
		HttpEntity httpEntity = null;
		switch (requestInfo.getMethodOption()) {
			case GET:
				requestBuilder.GET();
				httpEntity = generateEntity(requestInfo.getParameters(), null);
				break;
			case POST:
				if (requestInfo.getPostData() != null) {
					requestBuilder.POST(HttpRequest.BodyPublishers.ofByteArray(requestInfo.getPostData()));
				} else {
					try {
						ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
						httpEntity = generateEntity(requestInfo.getParameters(), requestInfo.getUploadParam());
						httpEntity.writeData(requestInfo.getCharset(), byteArrayOutputStream);
						requestBuilder.POST(HttpRequest.BodyPublishers.ofByteArray(byteArrayOutputStream.toByteArray()));
					} catch (IOException e) {
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Process_Data_Request_Error", e);
						}
						return null;
					}
				}
				break;
			case PUT:
				if (requestInfo.getPostData() != null) {
					requestBuilder.PUT(HttpRequest.BodyPublishers.ofByteArray(requestInfo.getPostData()));
				} else {
					try {
						ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
						httpEntity = generateEntity(requestInfo.getParameters(), requestInfo.getUploadParam());
						httpEntity.writeData(requestInfo.getCharset(), byteArrayOutputStream);
						requestBuilder.PUT(HttpRequest.BodyPublishers.ofByteArray(byteArrayOutputStream.toByteArray()));
					} catch (IOException e) {
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Process_Data_Request_Error", e);
						}
						return null;
					}
				}
				break;
			case DELETE:
				requestBuilder.DELETE();
				httpEntity = generateEntity(requestInfo.getParameters(), null);
				break;
			default:
				requestBuilder.method(requestInfo.getMethodOption().toString(), HttpRequest.BodyPublishers.noBody());
				httpEntity = generateEntity(requestInfo.getParameters(), null);
				break;
		}

		String uri = requestInfo.getRequestUrl();
		if (httpEntity != null) {
			try {
				requestBuilder.header("Content-Type",
						httpEntity.generateContentType(requestInfo.getCharset(), requestInfo.getMethodOption()));
			} catch (UnsupportedEncodingException e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Process_Content_Type_Request_Error", e);
				}
			}
			if (!HttpMethodOption.POST.equals(requestInfo.getMethodOption())
					&& !HttpMethodOption.PUT.equals(requestInfo.getMethodOption())) {
				uri = appendParams(uri, requestInfo.getParameters());
			}
		} else {
			requestBuilder.header("Content-Type",
					requestInfo.getContentType() + ";charset=" + requestInfo.getCharset());
		}

		requestInfo.getHeaders()
				.forEach(simpleHeader ->
						requestBuilder.setHeader(simpleHeader.getHeaderName(), simpleHeader.getHeaderValue()));
		requestBuilder.uri(URI.create(uri));

		requestBuilder.setHeader("Accept", "text/html,text/javascript,text/xml");
		requestBuilder.setHeader("Accept-Encoding", "gzip, deflate");
		if (StringUtils.isEmpty(requestInfo.getUserAgent())) {
			requestBuilder.setHeader("User-Agent", "NervousyncBot");
		} else {
			requestBuilder.setHeader("User-Agent", requestInfo.getUserAgent());
		}
		String cookie = generateCookie(requestInfo.getRequestUrl(), requestInfo.getCookieList());
		if (StringUtils.notBlank(cookie)) {
			requestBuilder.setHeader("Cookie", cookie);
		}

		HttpClient.Builder clientBuilder = HttpClient.newBuilder()
				.version(HttpClient.Version.HTTP_2)
				.followRedirects(HttpClient.Redirect.NORMAL);
		if (requestInfo.getTimeOut() > 0) {
			clientBuilder.connectTimeout(Duration.ofSeconds(requestInfo.getTimeOut()));
		}

		if (requestInfo.getProxyInfo() != null) {
			ProxyConfig proxyConfig = requestInfo.getProxyInfo();
			clientBuilder.proxy(ProxySelector.of(new InetSocketAddress(proxyConfig.getProxyAddress(), proxyConfig.getProxyPort())));
			if (StringUtils.notBlank(proxyConfig.getUserName())) {
				String authentication = proxyConfig.getUserName() + ":";
				if (StringUtils.notBlank(proxyConfig.getPassword())) {
					authentication += proxyConfig.getPassword();
				}

				requestBuilder.setHeader("Proxy-Authorization",
						StringUtils.base64Encode(authentication.getBytes(Charset.forName(Globals.DEFAULT_ENCODING))));
			}
		}

		if (requestInfo.getTrustCertInfos() != null && !requestInfo.getTrustCertInfos().isEmpty()) {
			try {
				System.setProperty("jdk.internal.httpclient.disableHostnameVerification", Boolean.TRUE.toString());
				SSLContext sslContext = SSLContext.getInstance("TLS");
				GeneX509TrustManager x509TrustManager =
						GeneX509TrustManager.newInstance(requestInfo.getPassPhrase(), requestInfo.getTrustCertInfos());
				sslContext.init(new KeyManager[0], new TrustManager[]{x509TrustManager}, new SecureRandom());
				clientBuilder.sslContext(sslContext);
			} catch (Exception e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Process_SSL_Certificate_Request_Error", e);
				}
			}
		}

		try {
			return Optional.ofNullable(clientBuilder.build()
							.send(requestBuilder.build(), new ResponseContentHandler())
							.body()
							.get())
					.map(responseInfo -> {
						if (ResponseInfo.class.equals(targetClass)) {
							return targetClass.cast(responseInfo);
						}
						if (targetClass.isArray() || ClassUtils.isAssignable(targetClass, Collection.class)) {
							return targetClass.cast(responseInfo.parseList(ClassUtils.componentType(targetClass)));
						} else {
							return responseInfo.parseObject(targetClass);
						}
					})
					.orElse(null);
		} catch (IOException | InterruptedException e) {
			LOGGER.error("Send_Request_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return null;
		} finally {
			System.clearProperty("jdk.internal.httpclient.disableHostnameVerification");
		}
	}

	/**
	 * <h3 class="en-US">Generate query string from given request instance</h3>
	 * <h3 class="zh-CN">从给定的请求实例对象中解析并生成查询字符串</h3>
	 *
	 * @param request <span class="en-US">Request instance</span>
	 *                <span class="zh-CN">请求实例对象</span>
	 * @return <span class="en-US">Generated query string</span>
	 * <span class="zh-CN">生成的查询字符串</span>
	 */
	public static String createQueryString(final HttpServletRequest request) {
		return createQueryStringFromMap(request.getParameterMap(), "&").toString();
	}

	/**
	 * <h3 class="en-US">Generate parameter map from query string</h3>
	 * <h3 class="zh-CN">从给定的查询字符串生成参数映射表</h3>
	 *
	 * @param queryString <span class="en-US">query string</span>
	 *                    <span class="zh-CN">查询字符串</span>
	 * @return <span class="en-US">Generated parameter map</span>
	 * <span class="zh-CN">生成的参数映射表</span>
	 */
	public static Map<String, String[]> parseQueryString(final String queryString) {
		return parseQueryString(queryString, Boolean.TRUE, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Generate parameter map from query string</h3>
	 * <h3 class="zh-CN">从给定的查询字符串生成参数映射表</h3>
	 *
	 * @param queryString <span class="en-US">query string</span>
	 *                    <span class="zh-CN">查询字符串</span>
	 * @param parseMatrix <span class="en-US">parse matrix parameter</span>
	 *                    <span class="zh-CN">解析矩阵参数</span>
	 * @return <span class="en-US">Generated parameter map</span>
	 * <span class="zh-CN">生成的参数映射表</span>
	 */
	public static Map<String, String[]> parseQueryString(final String queryString, final boolean parseMatrix) {
		return parseQueryString(queryString, Boolean.TRUE, parseMatrix);
	}

	/**
	 * <h3 class="en-US">Generate parameter map from query string</h3>
	 * <h3 class="zh-CN">从给定的查询字符串生成参数映射表</h3>
	 *
	 * @param queryString  <span class="en-US">query string</span>
	 *                     <span class="zh-CN">查询字符串</span>
	 * @param decodeValues <span class="en-US">Decode parameter value</span>
	 *                     <span class="zh-CN">解码参数值</span>
	 * @param parseMatrix  <span class="en-US">parse matrix parameter</span>
	 *                     <span class="zh-CN">解析矩阵参数</span>
	 * @return <span class="en-US">Generated parameter map</span>
	 * <span class="zh-CN">生成的参数映射表</span>
	 */
	public static Map<String, String[]> parseQueryString(final String queryString, final boolean decodeValues,
	                                                     final boolean parseMatrix) {
		HashMap<String, String[]> parameterMap = new HashMap<>();

		if (queryString == null) {
			return parameterMap;
		}

		for (int k = 0; k < queryString.length(); ) {
			int ampPos = queryString.indexOf('&', k);
			if (ampPos == -1) {
				ampPos = queryString.length();
			}
			String parameter = queryString.substring(k, ampPos);
			int equalsSignPos = parameter.indexOf('=');
			if (equalsSignPos != -1) {
				String key = parameter.substring(0, equalsSignPos);
				String value = parameter.substring(equalsSignPos + 1).trim();
				try {
					key = URLDecoder.decode(key, Globals.DEFAULT_ENCODING);
					if (decodeValues) {
						value = URLDecoder.decode(value, Globals.DEFAULT_ENCODING);
					}
					if (parseMatrix) {
						int splitIndex = value.indexOf(";");
						if (splitIndex == Globals.DEFAULT_VALUE_INT) {

							parameterMap.put(key, StringUtils.mergeStringArrays(parameterMap.get(key), value));
						} else {
							String paramValue = value.substring(0, splitIndex);
							parameterMap.put(key, StringUtils.mergeStringArrays(parameterMap.get(key), paramValue));

							Arrays.asList(StringUtils.tokenizeToStringArray(value.substring(splitIndex), ";"))
									.forEach(matrixString -> parseMatrixString(parameterMap, matrixString));
						}
					} else {
						parameterMap.put(key, StringUtils.mergeStringArrays(parameterMap.get(key), value));
					}
				} catch (UnsupportedEncodingException e) {
					// do nothing
				}
			}
			k = ampPos + 1;
		}

		return parameterMap;
	}

	/**
	 * <h3 class="en-US">Generate parameter map from uri string</h3>
	 * <h3 class="zh-CN">从给定的查询字符串生成参数映射表</h3>
	 *
	 * @param uri <span class="en-US">uri string</span>
	 *            <span class="zh-CN">uri字符串</span>
	 * @return <span class="en-US">Generated parameter map</span>
	 * <span class="zh-CN">生成的参数映射表</span>
	 */
	public static Map<String, String[]> parseParametersFromUri(final String uri) {
		return parseParametersFromUri(uri, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Generate parameter map from uri string</h3>
	 * <h3 class="zh-CN">从给定的查询字符串生成参数映射表</h3>
	 *
	 * @param uri         <span class="en-US">uri string</span>
	 *                    <span class="zh-CN">uri字符串</span>
	 * @param parseMatrix <span class="en-US">parse matrix parameter</span>
	 *                    <span class="zh-CN">解析矩阵参数</span>
	 * @return <span class="en-US">Generated parameter map</span>
	 * <span class="zh-CN">生成的参数映射表</span>
	 */
	public static Map<String, String[]> parseParametersFromUri(final String uri, final boolean parseMatrix) {
		if (ObjectUtils.isNull(uri) || uri.trim().isEmpty()) {
			return new HashMap<>();
		}
		int qSignPos = uri.indexOf('?');
		if (qSignPos == -1) {
			return new HashMap<>();
		}
		return parseQueryString(uri.substring(qSignPos + 1), parseMatrix);
	}

	/**
	 * <h3 class="en-US">Retrieve request address from uri string</h3>
	 * <h3 class="zh-CN">从uri字符串中解析请求地址</h3>
	 *
	 * @param uri <span class="en-US">uri string</span>
	 *            <span class="zh-CN">uri字符串</span>
	 * @return <span class="en-US">Generated parameter map</span>
	 * <span class="zh-CN">生成的参数映射表</span>
	 */
	public static String getBaseFromUri(final String uri) {
		if (ObjectUtils.isNull(uri) || uri.trim().isEmpty()) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		int qSignPos = uri.indexOf('?');
		if (qSignPos == -1) {
			return uri;
		}
		return uri.substring(0, qSignPos);
	}

	/**
	 * <h3 class="en-US">Generate query string from given parameter map</h3>
	 * <h3 class="zh-CN">从给定的参数映射表中解析并生成查询字符串</h3>
	 *
	 * @param m         <span class="en-US">parameter map</span>
	 *                  <span class="zh-CN">参数映射表中</span>
	 * @param ampersand <span class="en-US">Concat string</span>
	 *                  <span class="zh-CN">参数连接字符</span>
	 * @return <span class="en-US">Generated query string</span>
	 * <span class="zh-CN">生成的查询字符串</span>
	 */
	public static StringBuilder createQueryStringFromMap(final Map<String, String[]> m, final String ampersand) {
		return createQueryStringFromMap(m, ampersand, true);
	}

	/**
	 * <h3 class="en-US">Generate query string from given parameter map</h3>
	 * <h3 class="zh-CN">从给定的参数映射表中解析并生成查询字符串</h3>
	 *
	 * @param m         <span class="en-US">parameter map</span>
	 *                  <span class="zh-CN">参数映射表中</span>
	 * @param ampersand <span class="en-US">Concat string</span>
	 *                  <span class="zh-CN">参数连接字符</span>
	 * @param encode    <span class="en-US">Encode parameter value</span>
	 *                  <span class="zh-CN">编码参数值</span>
	 * @return <span class="en-US">Generated query string</span>
	 * <span class="zh-CN">生成的查询字符串</span>
	 */
	public static StringBuilder createQueryStringFromMap(final Map<String, String[]> m, final String ampersand,
	                                                     final boolean encode) {
		StringBuilder result = new StringBuilder();
		Set<Entry<String, String[]>> entrySet = m.entrySet();

		for (Entry<String, String[]> entry : entrySet) {
			String[] values = entry.getValue();
			String key = entry.getKey();
			if (result.length() > 0) {
				result.append(ampersand);
			}
			try {
				if (values == null) {
					result.append(encode ? URLEncoder.encode(key, Globals.DEFAULT_ENCODING) : key)
							.append("=")
							.append(Globals.DEFAULT_VALUE_STRING);
				} else {
					for (String value : values) {
						result.append(encode ? URLEncoder.encode(key, Globals.DEFAULT_ENCODING) : key)
								.append("=")
								.append(encode ? URLEncoder.encode(value, Globals.DEFAULT_ENCODING) : value);
					}
				}
			} catch (UnsupportedEncodingException e) {
				// do nothing
			}
		}

		return result;
	}

	/**
	 * <h3 class="en-US">Append generated query string to given uri string</h3>
	 * <h3 class="zh-CN">追加生成的查询字符串到给定的uri字符串后</h3>
	 *
	 * @param uri    <span class="en-US">uri string</span>
	 *               <span class="zh-CN">uri字符串</span>
	 * @param params <span class="en-US">parameter map</span>
	 *               <span class="zh-CN">参数映射表中</span>
	 * @return <span class="en-US">Appended uri string</span>
	 * <span class="zh-CN">追加后的uri字符串</span>
	 */
	public static String appendParams(final String uri, final Map<String, String[]> params) {
		String delimiter = (uri.indexOf('?') == -1) ? "?" : "&";
		return uri + delimiter + createQueryStringFromMap(params, "&");
	}

	/**
	 * <h3 class="en-US">Save request attribute values to session</h3>
	 * <h3 class="zh-CN">将给定的请求参数信息保存到session中</h3>
	 *
	 * @param request <span class="en-US">Request instance</span>
	 *                <span class="zh-CN">请求实例对象</span>
	 */
	public static void stowRequestAttributes(@Nonnull final HttpServletRequest request) {
		if (request.getSession().getAttribute(STOWED_REQUEST_ATTRIBS) == null) {
			request.getSession().setAttribute(STOWED_REQUEST_ATTRIBS, new RequestAttribute(request));
		}
	}

	/**
	 * <h3 class="en-US">Read request attribute values from session and save to request</h3>
	 * <h3 class="zh-CN">从session中读取保存的参数信息并保存到请求中</h3>
	 *
	 * @param request <span class="en-US">Request instance</span>
	 *                <span class="zh-CN">请求实例对象</span>
	 */
	public static void reclaimRequestAttributes(@Nonnull final HttpServletRequest request) {
		HttpSession httpSession = request.getSession(Boolean.FALSE);
		Optional.ofNullable(httpSession)
				.map(session -> session.getAttribute(STOWED_REQUEST_ATTRIBS))
				.map(requestAttribute -> (RequestAttribute) requestAttribute)
				.ifPresent(requestAttribute -> {
					requestAttribute.getAttributeMap().forEach(request::setAttribute);
					httpSession.removeAttribute(STOWED_REQUEST_ATTRIBS);
				});
	}

	/**
	 * <h3 class="en-US">Retrieve full request address from request instance</h3>
	 * <h3 class="zh-CN">从请求实例对象中获取完整的请求地址</h3>
	 *
	 * @param request <span class="en-US">Request instance</span>
	 *                <span class="zh-CN">请求实例对象</span>
	 */
	public static String getAppURL(final HttpServletRequest request) {
		StringBuilder requestUrl = new StringBuilder();
		int port = request.getServerPort();
		if (port < 0) {
			port = 80; // Work around java.net.URL bug
		}
		String scheme = request.getScheme();
		requestUrl.append(scheme);
		requestUrl.append("://");
		requestUrl.append(request.getServerName());
		if ((scheme.equalsIgnoreCase("http") && (port != 80))
				|| (scheme.equalsIgnoreCase("https") && (port != 443))) {
			requestUrl.append(':');
			requestUrl.append(port);
		}
		requestUrl.append(request.getContextPath());
		return requestUrl.toString();
	}

	/**
	 * <h3 class="en-US">Check roles iterator is authenticated by request instance</h3>
	 * <h3 class="zh-CN">检查请求实例对象中是否有给定的角色代码授权</h3>
	 *
	 * @param rolesIterator <span class="en-US">Role codes iterator instance</span>
	 *                      <span class="zh-CN">角色代码遍历器</span>
	 * @param request       <span class="en-US">Request instance</span>
	 *                      <span class="zh-CN">请求实例对象</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean isUserInRole(final Iterator<Object> rolesIterator, final HttpServletRequest request) {
		return isUserInRole(rolesIterator, null, request);
	}

	/**
	 * <h3 class="en-US">Check roles iterator is authenticated by request instance</h3>
	 * <h3 class="zh-CN">检查请求实例对象中是否有给定的角色代码授权</h3>
	 *
	 * @param rolesIterator <span class="en-US">Role codes iterator instance</span>
	 *                      <span class="zh-CN">角色代码遍历器</span>
	 * @param property      <span class="en-US">Property field name</span>
	 *                      <span class="zh-CN">属性名</span>
	 * @param request       <span class="en-US">Request instance</span>
	 *                      <span class="zh-CN">请求实例对象</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean isUserInRole(final Iterator<Object> rolesIterator, final String property,
	                                   final HttpServletRequest request) {
		if (rolesIterator != null) {
			while (rolesIterator.hasNext()) {
				Object bean = rolesIterator.next();
				if (bean == null) {
					continue;
				}
				String roleName;
				if (bean instanceof String) {
					roleName = (String) bean;
				} else if (property != null && !property.trim().isEmpty()) {
					roleName = String.valueOf(ReflectionUtils.getFieldValue(property, bean));
				} else {
					roleName = String.valueOf(bean);
				}

				if (request.isUserInRole(roleName.trim())) {
					return Boolean.TRUE;
				}
			}
		} else {
			// if no role is specified, grant access
			return Boolean.TRUE;
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Retrieve client IP address from given request instance</h3>
	 * <h3 class="zh-CN">从请求实例对象中获取客户端IP地址</h3>
	 *
	 * @param request <span class="en-US">Request instance</span>
	 *                <span class="zh-CN">请求实例对象</span>
	 * @return <span class="en-US">Client IP address</span>
	 * <span class="zh-CN">客户端IP地址</span>
	 */
	public static String getClientIP(final HttpServletRequest request) {
		request.getHeaderNames();
		//	如果使用了反向代理服务器，则需要从Header中获取转发的客户端IP地址
		String clientIP = request.getHeader("X-Forwarded-For");

		if (StringUtils.isEmpty(clientIP) || "unknown".equalsIgnoreCase(clientIP)) {
			clientIP = request.getHeader("Proxy-Client-IP");
		}

		if (StringUtils.isEmpty(clientIP) || "unknown".equalsIgnoreCase(clientIP)) {
			clientIP = request.getHeader("WL-Proxy-Client-IP");
		}

		if (StringUtils.isEmpty(clientIP) || "unknown".equalsIgnoreCase(clientIP)) {
			clientIP = request.getHeader("HTTP_CLIENT_IP");
		}

		if (StringUtils.isEmpty(clientIP) || "unknown".equalsIgnoreCase(clientIP)) {
			clientIP = request.getHeader("HTTP_X_FORWARDED_FOR");
		}

		if (StringUtils.isEmpty(clientIP) || "unknown".equalsIgnoreCase(clientIP)) {
			clientIP = request.getRemoteAddr();
		}

		int index = clientIP.indexOf(',');

		if (index == -1) {
			return clientIP;
		} else {
			//	使用了多级反向代理服务器
			return clientIP.substring(0, index);
		}
	}

	/**
	 * <h3 class="en-US">Retrieve request uri string from request instance</h3>
	 * <h3 class="zh-CN">从请求实例对象中获取uri字符串</h3>
	 *
	 * @param request <span class="en-US">Request instance</span>
	 *                <span class="zh-CN">请求实例对象</span>
	 * @return <span class="en-US">uri string or empty string if request instance is <code>null</code></span>
	 * <span class="zh-CN">uri字符串，如果请求实例对象为<code>null</code>则返回空字符串</span>
	 */
	public static String getRequestURI(final HttpServletRequest request) {
		String requestUrl = getRequestPath(request);

		if (requestUrl.lastIndexOf('.') != -1) {
			return requestUrl.substring(0, requestUrl.lastIndexOf("."));
		}
		return requestUrl;
	}

	/**
	 * <h3 class="en-US">Retrieve request path exclude context path</h3>
	 * <h3 class="zh-CN">获取不包含上下文地址的请求路径</h3>
	 *
	 * @param request <span class="en-US">Request instance</span>
	 *                <span class="zh-CN">请求实例对象</span>
	 * @return <span class="en-US">request path or empty string if request instance is <code>null</code></span>
	 * <span class="zh-CN">请求地址，如果请求实例对象为<code>null</code>则返回空字符串</span>
	 */
	public static String getRequestPath(final HttpServletRequest request) {
		if (request == null) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		String requestUrl = request.getRequestURI();

		if (StringUtils.notBlank(request.getContextPath())) {
			requestUrl = requestUrl.substring(request.getContextPath().length());
		}
		return requestUrl;
	}

	public static String getRequestUrl(final HttpServletRequest request) {
		return getRequestUrl(request, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Retrieve request url address</h3>
	 * <h3 class="zh-CN">获取请求的url地址</h3>
	 *
	 * @param request       <span class="en-US">Request instance</span>
	 *                      <span class="zh-CN">请求实例对象</span>
	 * @param includeDomain <span class="en-US">Include domain name</span>
	 *                      <span class="zh-CN">包含域名</span>
	 * @return <span class="en-US">Retrieved url address or empty string if request instance is <code>null</code></span>
	 * <span class="zh-CN">获取的的url地址，如果请求实例对象为<code>null</code>则返回空字符串</span>
	 */
	public static String getRequestUrl(final HttpServletRequest request, final boolean includeDomain) {
		if (request == null) {
			return Globals.DEFAULT_VALUE_STRING;
		}

		StringBuilder requestUrl = new StringBuilder();

		if (includeDomain) {
			requestUrl.append(getAppURL(request));
		}

		requestUrl.append(getRequestURI(request));

		if (request.getQueryString() != null && !request.getQueryString().isEmpty()) {
			requestUrl.append("?").append(request.getQueryString());
		}

		return requestUrl.toString();
	}

	/**
	 * <h3 class="en-US">Process url rewrite</h3>
	 * <h3 class="zh-CN">处理URL重写</h3>
	 *
	 * @param request <span class="en-US">Request instance</span>
	 *                <span class="zh-CN">请求实例对象</span>
	 * @param regex   <span class="en-US">Rewrite regex string</span>
	 *                <span class="zh-CN">重写的正则表达式</span>
	 * @param toPath  <span class="en-US">Rewrite url template</span>
	 *                <span class="zh-CN">重写url的模板</span>
	 * @return <span class="en-US">Rewrite url address or null if original <code>null</code> address not matched</span>
	 * <span class="zh-CN">重写后的url地址，如果原始地址未匹配正则表达式，则返回<code>null</code></span>
	 */
	public static String processRewrite(final HttpServletRequest request, final String regex, final String toPath) {
		String rewriteUrl = StringUtils.replaceWithRegex(getRequestUrl(request, Boolean.FALSE), regex, toPath, "/");
		if (StringUtils.notBlank(rewriteUrl)) {
			String queryString = createQueryString(request);
			if (StringUtils.notBlank(queryString)) {
				return rewriteUrl + (rewriteUrl.contains("?") ? "&" : "?") + queryString;
			}
		}
		return rewriteUrl;
	}

	/**
	 * <h3 class="en-US">Parse matrix string and merge value to given parameter map</h3>
	 * <h3 class="zh-CN">解析矩阵参数值，合并到给定的参数映射表中</h3>
	 *
	 * @param parameterMap <span class="en-US">parameter map</span>
	 *                     <span class="zh-CN">参数映射表</span>
	 * @param matrixString <span class="en-US">matrix string</span>
	 *                     <span class="zh-CN">矩阵参数值</span>
	 */
	private static void parseMatrixString(final Map<String, String[]> parameterMap, final String matrixString) {
		if (StringUtils.isEmpty(matrixString)) {
			return;
		}
		int equalIndex = matrixString.indexOf("=");
		if (equalIndex != Globals.DEFAULT_VALUE_INT) {
			String matrixKey = matrixString.substring(0, equalIndex);
			String matrixValue = matrixString.substring(equalIndex + 1);

			parameterMap.put(matrixKey, StringUtils.mergeStringArrays(parameterMap.get(matrixKey), matrixValue));
		}
	}

	/**
	 * <h3 class="en-US">Generate value of request header "Cookie"</h3>
	 * <h3 class="zh-CN">生成请求头"Cookie"的值</h3>
	 *
	 * @param requestUrl <span class="en-US">Request url</span>
	 *                   <span class="zh-CN">请求地址</span>
	 * @param cookieList <span class="en-US">Cookie information list</span>
	 *                   <span class="zh-CN">Cookie信息列表</span>
	 * @return <span class="en-US">Generated value string</span>
	 * <span class="zh-CN">生成的结果字符串</span>
	 */
	private static String generateCookie(final String requestUrl, final List<CookieEntity> cookieList) {
		if (cookieList == null || cookieList.isEmpty()) {
			return null;
		}
		StringBuilder stringBuilder = new StringBuilder();

		for (CookieEntity cookieInfo : cookieList) {
			if ((!requestUrl.startsWith(Globals.SECURE_HTTP_PROTOCOL)
					&& cookieInfo.isSecure()) || (cookieInfo.getExpires() > DateTimeUtils.currentUTCTimeMillis())
					|| cookieInfo.getMaxAge() == Globals.DEFAULT_VALUE_LONG || cookieInfo.getMaxAge() == 0L) {
				continue;
			}

			String domain;
			String requestPath;

			if (requestUrl.startsWith(Globals.SECURE_HTTP_PROTOCOL)) {
				domain = requestUrl.substring(Globals.SECURE_HTTP_PROTOCOL.length());
			} else if (requestUrl.startsWith(Globals.HTTP_PROTOCOL)) {
				domain = requestUrl.substring(Globals.HTTP_PROTOCOL.length());
			} else {
				return null;
			}

			if (domain.indexOf("/") > 0) {
				requestPath = domain.substring(domain.indexOf("/") + 1);
				domain = domain.substring(0, domain.indexOf("/"));
			} else {
				requestPath = "/";
			}

			if (!domain.toLowerCase().endsWith(cookieInfo.getDomain().toLowerCase())
					|| !requestPath.startsWith(cookieInfo.getPath())) {
				continue;
			}

			stringBuilder.append("; ").append(cookieInfo.getName()).append("=").append(cookieInfo.getValue());
		}

		if (stringBuilder.length() == 0) {
			return null;
		}
		return stringBuilder.substring(2);
	}

	/**
	 * <h3 class="en-US">Generate entity of http request</h3>
	 * <h3 class="zh-CN">生成Http请求的请求体</h3>
	 *
	 * @param parameters    <span class="en-US">parameter map</span>
	 *                      <span class="zh-CN">参数映射表</span>
	 * @param uploadFileMap <span class="en-US">upload file map</span>
	 *                      <span class="zh-CN">上传文件映射表</span>
	 * @return <span class="en-US">Generated HttpEntity instance</span>
	 * <span class="zh-CN">生成的HttpEntity实例对象</span>
	 */
	private static HttpEntity generateEntity(Map<String, String[]> parameters, Map<String, File> uploadFileMap) {
		if (parameters == null) {
			parameters = new HashMap<>();
		}

		HttpEntity httpEntity = new HttpEntity();
		parameters.forEach((key, values) -> {
			for (String value : values) {
				httpEntity.addTextEntity(key, value);
			}
		});

		if (uploadFileMap != null && !uploadFileMap.isEmpty()) {
			uploadFileMap.forEach((key, uploadFile) -> {
				if (uploadFile != null) {
					httpEntity.addBinaryEntity(key, uploadFile.getAbsolutePath());
				}
			});
		}

		return httpEntity;
	}

	/**
	 * <h2 class="en-US">Response Content Handler</h2>
	 * <h2 class="zh-CN">响应体拦截处理器</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0.0 $ $Date: May 13, 2014 17:22:48 $
	 */
	private static final class ResponseContentHandler implements HttpResponse.BodyHandler<Supplier<ResponseInfo>> {
		/**
		 * <h3 class="en-US">Constructor for ResponseContentHandler</h3>
		 * <h3 class="zh-CN">响应体拦截处理器的构造方法</h3>
		 */
		ResponseContentHandler() {
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see HttpResponse.BodyHandler#apply(HttpResponse.ResponseInfo)
		 */
		public HttpResponse.BodySubscriber<Supplier<ResponseInfo>> apply(HttpResponse.ResponseInfo responseInfo) {
			HttpResponse.BodySubscriber<InputStream> upstream = HttpResponse.BodySubscribers.ofInputStream();
			return HttpResponse.BodySubscribers.mapping(upstream,
					inputStream -> () -> new ResponseInfo(responseInfo, inputStream));
		}
	}
}
