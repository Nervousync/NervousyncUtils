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

import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.*;
import jakarta.ws.rs.client.*;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.xml.ws.BindingProvider;
import jakarta.xml.ws.Service;
import jakarta.xml.ws.WebServiceClient;
import jakarta.xml.ws.handler.HandlerResolver;
import org.nervousync.annotations.beans.DataTransfer;
import org.nervousync.beans.config.TransferConfig;
import org.nervousync.commons.Globals;
import org.nervousync.enumerations.web.HttpMethodOption;
import org.nervousync.exceptions.beans.network.NetworkInfoException;
import org.nervousync.exceptions.services.ServiceException;

import javax.xml.namespace.QName;
import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.*;

/**
 * <h2 class="en-US">Service utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Generate SOAP Client instance</ul>
 *     <ul>Generate Restful Client and process request</ul>
 * </span>
 * <h2 class="zh-CN">网络服务工具集</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>生成SOAP请求客户端</ul>
 *     <ul>生成Restful请求客户端并处理请求</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Jan 13, 2020 15:52:33 $
 */
public final class ServiceUtils {
	/**
	 * <span class="en-US">Multilingual supported logger instance</span>
	 * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(ServiceUtils.class);

	/**
	 * <h3 class="en-US">Private constructor for ServiceUtils</h3>
	 * <h3 class="zh-CN">网络服务工具集的私有构造方法</h3>
	 */
	private ServiceUtils() {
	}

	/**
	 * <h3 class="en-US">Generate SOAP Client instance</h3>
	 * <h3 class="zh-CN">生成SOAP请求客户端</h3>
	 *
	 * @param <T>              <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @param serviceLocation  <span class="en-US">Web service location</span>
	 *                         <span class="zh-CN">Web服务地址</span>
	 * @param serviceInterface <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @return <span class="en-US">Generated client instance</span>
	 * <span class="zh-CN">生成的客户端实例对象</span>
	 * @throws MalformedURLException <span class="en-US">if no protocol is specified, or an unknown protocol is found, or spec is null.</span>
	 *                               <span class="zh-CN">如果没有指定协议，或者发现未知协议，或者spec为空。</span>
	 */
	public static <T> T SOAPClient(final String serviceLocation, final Class<T> serviceInterface)
			throws MalformedURLException {
		return SOAPClient(serviceLocation, serviceInterface, Map.of());
	}

	/**
	 * <h3 class="en-US">Generate SOAP Client instance</h3>
	 * <h3 class="zh-CN">生成SOAP请求客户端</h3>
	 *
	 * @param <T>              <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @param serviceLocation  <span class="en-US">Web service location</span>
	 *                         <span class="zh-CN">Web服务地址</span>
	 * @param serviceInterface <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @return <span class="en-US">Generated client instance</span>
	 * <span class="zh-CN">生成的客户端实例对象</span>
	 * @throws MalformedURLException <span class="en-US">if no protocol is specified, or an unknown protocol is found, or spec is null.</span>
	 *                               <span class="zh-CN">如果没有指定协议，或者发现未知协议，或者spec为空。</span>
	 */
	public static <T> T SOAPClient(final String serviceLocation, final Class<T> serviceInterface,
	                               final Map<String, Object> configMap) throws MalformedURLException {
		return SOAPClient(serviceLocation, serviceInterface, null, configMap);
	}

	/**
	 * <h3 class="en-US">Generate SOAP Client instance</h3>
	 * <h3 class="zh-CN">生成SOAP请求客户端</h3>
	 *
	 * @param <T>              <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @param serviceLocation  <span class="en-US">Web service location</span>
	 *                         <span class="zh-CN">Web服务地址</span>
	 * @param serviceInterface <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @param handlerResolver  <span class="en-US">Custom handler resolver instance</span>
	 *                         <span class="zh-CN">自定义的处理器实例对象</span>
	 * @return <span class="en-US">Generated client instance</span>
	 * <span class="zh-CN">生成的客户端实例对象</span>
	 * @throws MalformedURLException <span class="en-US">if no service location, protocol is specified, or an unknown protocol is found, or spec is null.</span>
	 *                               <span class="zh-CN">如果没有指定服务地址、协议，或者发现未知协议，或者spec为空。</span>
	 */
	public static <T> T SOAPClient(final String serviceLocation, final Class<T> serviceInterface,
	                               final HandlerResolver handlerResolver)
			throws MalformedURLException {
		return SOAPClient(serviceLocation, serviceInterface, handlerResolver, null);
	}

	/**
	 * <h3 class="en-US">Generate SOAP Client instance</h3>
	 * <h3 class="zh-CN">生成SOAP请求客户端</h3>
	 *
	 * @param <T>              <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @param serviceLocation  <span class="en-US">Web service location</span>
	 *                         <span class="zh-CN">Web服务地址</span>
	 * @param serviceInterface <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @param handlerResolver  <span class="en-US">Custom handler resolver instance</span>
	 *                         <span class="zh-CN">自定义的处理器实例对象</span>
	 * @param configMap        <span class="en-US">Configure information map</span>
	 *                         <span class="zh-CN">配置信息映射表</span>
	 * @return <span class="en-US">Generated client instance</span>
	 * <span class="zh-CN">生成的客户端实例对象</span>
	 * @throws MalformedURLException <span class="en-US">if no service location, protocol is specified, or an unknown protocol is found, or spec is null.</span>
	 *                               <span class="zh-CN">如果没有指定服务地址、协议，或者发现未知协议，或者spec为空。</span>
	 */
	public static <T> T SOAPClient(final String serviceLocation, final Class<T> serviceInterface,
	                               final HandlerResolver handlerResolver, final Map<String, Object> configMap)
			throws MalformedURLException {
		if (StringUtils.isEmpty(serviceLocation)
				|| !serviceInterface.isAnnotationPresent(WebServiceClient.class)) {
			throw new MalformedURLException("Service location is empty or Annotation not found");
		}

		WebServiceClient serviceClient = serviceInterface.getAnnotation(WebServiceClient.class);

		String namespaceURI = serviceClient.targetNamespace();
		String serviceName = serviceClient.name();
		URL wsdlLocation = new URL(serviceLocation + Globals.DEFAULT_RESOURCE_SEPARATOR + serviceClient.wsdlLocation());

		if (namespaceURI.isEmpty()) {
			String packageName = serviceInterface.getPackage().getName();
			String[] packageNames = StringUtils.tokenizeToStringArray(packageName, ".");
			StringBuilder stringBuilder = new StringBuilder(wsdlLocation.getProtocol() + "://");
			for (int i = packageNames.length - 1; i >= 0; i--) {
				stringBuilder.append(packageNames[i]).append(".");
			}

			namespaceURI = stringBuilder.substring(0, stringBuilder.length() - 1) + "/";
		}

		if (StringUtils.isEmpty(serviceName)) {
			serviceName = serviceInterface.getSimpleName() + "Service";
		}

		Service service = Service.create(wsdlLocation, new QName(namespaceURI, serviceName));
		if (handlerResolver != null) {
			service.setHandlerResolver(handlerResolver);
		}

		T port = service.getPort(new QName(namespaceURI, serviceName), serviceInterface);

		if (configMap != null) {
			configMap.forEach((key, value) -> ((BindingProvider) port).getRequestContext().put(key, value));
		}

		return service.getPort(new QName(namespaceURI, serviceName), serviceInterface);
	}

	/**
	 * <h3 class="en-US">Generate Restful service client instance</h3>
	 * <h3 class="zh-CN">生成Restful请求客户端</h3>
	 *
	 * @param <T>              <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @param targetAddress    <span class="en-US">the target address</span>
	 *                         <span class="zh-CN">目标请求地址</span>
	 * @param serviceInterface <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @return <span class="en-US">Generated client instance</span>
	 * <span class="zh-CN">生成的客户端实例对象</span>
	 * @throws MalformedURLException <span class="en-US">if no service location.</span>
	 *                               <span class="zh-CN">如果没有指定服务地址。</span>
	 */
	public static <T> T RestfulClient(final String targetAddress, final Class<T> serviceInterface)
			throws MalformedURLException {
		return RestfulClient(targetAddress, serviceInterface, Map.of());
	}

	/**
	 * <h3 class="en-US">Generate Restful service client instance</h3>
	 * <h3 class="zh-CN">生成Restful请求客户端</h3>
	 *
	 * @param <T>              <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @param targetAddress    <span class="en-US">the target address</span>
	 *                         <span class="zh-CN">目标请求地址</span>
	 * @param serviceInterface <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @return <span class="en-US">Generated client instance</span>
	 * <span class="zh-CN">生成的客户端实例对象</span>
	 * @throws MalformedURLException <span class="en-US">if no service location.</span>
	 *                               <span class="zh-CN">如果没有指定服务地址。</span>
	 */
	public static <T> T RestfulClient(final String targetAddress, final ClientBuilder clientBuilder,
	                                  final Class<T> serviceInterface) throws MalformedURLException {
		return RestfulClient(targetAddress, clientBuilder, serviceInterface, Map.of());
	}

	/**
	 * <h3 class="en-US">Generate Restful service client instance</h3>
	 * <h3 class="zh-CN">生成Restful请求客户端</h3>
	 *
	 * @param <T>              <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @param targetAddress    <span class="en-US">the target address</span>
	 *                         <span class="zh-CN">目标请求地址</span>
	 * @param serviceInterface <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @param headerMap        <span class="en-US">Request header information map</span>
	 *                         <span class="zh-CN">请求头部信息映射</span>
	 * @return <span class="en-US">Generated client instance</span>
	 * <span class="zh-CN">生成的客户端实例对象</span>
	 * @throws MalformedURLException <span class="en-US">if no service location.</span>
	 *                               <span class="zh-CN">如果没有指定服务地址。</span>
	 */
	public static <T> T RestfulClient(final String targetAddress, final Class<T> serviceInterface,
	                                  final Map<String, String> headerMap) throws MalformedURLException {
		return RestfulClient(targetAddress, null, serviceInterface, headerMap);
	}

	/**
	 * <h3 class="en-US">Generate Restful service client instance</h3>
	 * <h3 class="zh-CN">生成Restful请求客户端</h3>
	 *
	 * @param <T>              <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @param targetAddress    <span class="en-US">the target address</span>
	 *                         <span class="zh-CN">目标请求地址</span>
	 * @param clientBuilder    <span class="en-US">Client builder instance object</span>
	 *                         <span class="zh-CN">客户端构建器</span>
	 * @param serviceInterface <span class="en-US">End point interface</span>
	 *                         <span class="zh-CN">Web服务的接口</span>
	 * @param headerMap        <span class="en-US">Request header information map</span>
	 *                         <span class="zh-CN">请求头部信息映射</span>
	 * @return <span class="en-US">Generated client instance</span>
	 * <span class="zh-CN">生成的客户端实例对象</span>
	 * @throws MalformedURLException <span class="en-US">if no service location.</span>
	 *                               <span class="zh-CN">如果没有指定服务地址。</span>
	 */
	public static <T> T RestfulClient(final String targetAddress, final ClientBuilder clientBuilder,
	                                  final Class<T> serviceInterface, final Map<String, String> headerMap)
			throws MalformedURLException {
		if (StringUtils.isEmpty(targetAddress)) {
			throw new MalformedURLException("Service location is empty");
		}
		String servicePath = targetAddress.toLowerCase().startsWith("http")
				? targetAddress
				: Globals.HTTP_PROTOCOL + targetAddress;
		if (serviceInterface.isAnnotationPresent(Path.class)) {
			servicePath += serviceInterface.getAnnotation(Path.class).value();
		}
		return ObjectUtils.newInstance(serviceInterface, new RestfulInterceptor(servicePath, clientBuilder, headerMap));
	}

	/**
	 * <h3 class="en-US">Append parameter value to current array</h3>
	 * <h3 class="zh-CN">追加参数值到当前数组</h3>
	 *
	 * @param paramValues <span class="en-US">Current array</span>
	 *                    <span class="zh-CN">当前数组</span>
	 * @param appendValue <span class="en-US">Append parameter value</span>
	 *                    <span class="zh-CN">追加的参数值</span>
	 * @return <span class="en-US">Append parameter value array</span>
	 * <span class="zh-CN">追加后的参数值数组</span>
	 */
	private static String[] appendValue(final String[] paramValues, final String appendValue) {
		String[] newValues = Arrays.copyOf(paramValues, paramValues.length + 1);
		newValues[paramValues.length] = Objects.requireNonNullElse(appendValue, Globals.DEFAULT_VALUE_STRING);
		return newValues;
	}

	/**
	 * <h2 class="en-US">Restful service interceptor invocation handler</h2>
	 * <h2 class="zh-CN">Restful服务拦截器调用处理程序</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2020 16:28:15 $
	 */
	private static final class RestfulInterceptor implements InvocationHandler {
		/**
		 * <span class="en-US">Request path</span>
		 * <span class="zh-CN">请求地址</span>
		 */
		private final String requestPath;
		/**
		 * <span class="en-US">Client builder instance object</span>
		 * <span class="zh-CN">客户端构建器</span>
		 */
		private final ClientBuilder clientBuilder;
		/**
		 * <span class="en-US">Request header information map</span>
		 * <span class="zh-CN">请求头部信息映射</span>
		 */
		private final Map<String, String> headerMap;

		/**
		 * <h3 class="en-US">Constructor for RestfulInterceptor</h3>
		 * <h3 class="zh-CN">Restful服务拦截器的构造方法</h3>
		 *
		 * @param requestPath   <span class="en-US">Request path</span>
		 *                      <span class="zh-CN">请求地址</span>
		 * @param clientBuilder <span class="en-US">Client builder instance object</span>
		 *                      <span class="zh-CN">客户端构建器</span>
		 * @param headerMap     <span class="en-US">Request header information map</span>
		 *                      <span class="zh-CN">请求头部信息映射</span>
		 */
		RestfulInterceptor(final String requestPath, final ClientBuilder clientBuilder,
		                   final Map<String, String> headerMap) {
			this.requestPath = requestPath;
			this.clientBuilder = (clientBuilder == null) ? ClientBuilder.newBuilder() : clientBuilder;
			this.headerMap = new HashMap<>();
			if (headerMap != null) {
				this.headerMap.putAll(headerMap);
			}
		}

		private String servicePath(final Method method) throws NetworkInfoException {
			if (!method.isAnnotationPresent(Path.class)) {
				throw new NetworkInfoException(0x0000001A0004L, "Unknown_Path_Restful_Service_Method");
			}

			String methodName = method.getAnnotation(Path.class).value();
			if (methodName.isEmpty()) {
				methodName = method.getName();
			} else if (methodName.startsWith("/")) {
				methodName = methodName.substring(1);
			}
			return this.requestPath + "/" + methodName;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see InvocationHandler#invoke(Object, Method, Object[])
		 */
		@Override
		public Object invoke(final Object o, final Method method, final Object[] objects) throws Throwable {
			HttpMethodOption methodOption = RequestUtils.httpMethodOption(method);
			if (HttpMethodOption.UNKNOWN.equals(methodOption)) {
				throw new NetworkInfoException(0x0000001A0003L, "Unknown_Http_Method");
			}
			String servicePath = this.servicePath(method);

			Annotation[][] annotations = method.getParameterAnnotations();
			Class<?>[] parameterClasses = method.getParameterTypes();

			if (objects.length != parameterClasses.length) {
				throw new Exception("Mismatch arguments");
			}

			Map<String, String> formParameters = new HashMap<>();
			Map<String, String> queryParameters = new HashMap<>();
			Map<String, String[]> matrixParameters = new HashMap<>();

			String[] mediaTypes = method.isAnnotationPresent(Consumes.class)
					? method.getAnnotation(Consumes.class).value()
					: new String[0];

			for (int i = 0; i < objects.length; i++) {
				Object paramObj = objects[i];
				if (paramObj == null) {
					continue;
				}
				TransferConfig transferConfig =
						Arrays.stream(annotations[i])
								.filter(annotation -> annotation.annotationType().equals(DataTransfer.class))
								.findFirst()
								.map(annotation -> new TransferConfig((DataTransfer) annotation))
								.orElse(new TransferConfig(null));
				if (Arrays.stream(annotations[i])
						.anyMatch(annotation -> annotation.annotationType().equals(BeanParam.class))) {
					BeanParameter beanParameter = new BeanParameter(paramObj, mediaTypes, transferConfig);
					this.headerMap.putAll(beanParameter.getHeaders());
					for (Map.Entry<String, String> entry : beanParameter.getPaths().entrySet()) {
						if (StringUtils.isEmpty(entry.getKey()) || entry.getValue() == null) {
							throw new ServiceException(0x0000000F0001L);
						}
						String pathKey = "{" + entry.getKey() + "}";
						if (servicePath.indexOf(pathKey) > 0) {
							servicePath = StringUtils.replace(servicePath, pathKey,
									URLEncoder.encode(entry.getValue(), Globals.DEFAULT_ENCODING));
						}
					}
					formParameters.putAll(beanParameter.getFormParameters());
					queryParameters.putAll(beanParameter.getQueryParameters());
					matrixParameters.putAll(beanParameter.getMatrixParameters());
				} else if (Arrays.stream(annotations[i])
						.anyMatch(annotation -> annotation.annotationType().equals(MatrixParam.class))) {
					Arrays.stream(annotations[i])
							.filter(annotation -> annotation.annotationType().equals(MatrixParam.class))
							.findFirst()
							.map(annotation -> ((MatrixParam) annotation).value())
							.ifPresent(paramName -> {
								if (paramObj.getClass().isArray()) {
									Arrays.asList((Object[]) paramObj).forEach(itemValue -> {
										String paramValue = transferConfig.marshal(itemValue);
										matrixParameters.put(paramName,
												appendValue(matrixParameters.getOrDefault(paramName, new String[0]),
														paramValue));
									});
								} else if (List.class.isAssignableFrom(paramObj.getClass())) {
									((List<?>) paramObj).forEach(itemValue -> {
										String paramValue = transferConfig.marshal(itemValue);
										matrixParameters.put(paramName,
												appendValue(matrixParameters.getOrDefault(paramName, new String[0]),
														paramValue));
									});
								} else {
									String paramValue = transferConfig.marshal(paramObj);
									matrixParameters.put(paramName,
											appendValue(matrixParameters.getOrDefault(paramName, new String[0]),
													paramValue));
								}
							});
				} else {
					String paramValue = transferConfig.marshal(paramObj);
					if (Arrays.stream(annotations[i])
							.anyMatch(annotation -> annotation.annotationType().equals(QueryParam.class))) {
						String paramName =
								Arrays.stream(annotations[i]).filter(annotation ->
												annotation.annotationType().equals(QueryParam.class))
										.findFirst()
										.map(annotation -> ((QueryParam) annotation).value())
										.orElse(Globals.DEFAULT_VALUE_STRING);
						if (StringUtils.notBlank(paramName)) {
							queryParameters.put(paramName, paramValue);
						}
					}

					if (Arrays.stream(annotations[i])
							.anyMatch(annotation -> annotation.annotationType().equals(FormParam.class))) {
						String paramName =
								Arrays.stream(annotations[i]).filter(annotation ->
												annotation.annotationType().equals(FormParam.class))
										.findFirst()
										.map(annotation -> ((FormParam) annotation).value())
										.orElse(Globals.DEFAULT_VALUE_STRING);
						if (StringUtils.notBlank(paramName)) {
							queryParameters.put(paramName, paramValue);
						}
					}

					if (Arrays.stream(annotations[i])
							.anyMatch(annotation -> annotation.annotationType().equals(PathParam.class))) {
						String paramName =
								Arrays.stream(annotations[i]).filter(annotation ->
												annotation.annotationType().equals(PathParam.class))
										.findFirst()
										.map(annotation -> ((PathParam) annotation).value())
										.orElse(Globals.DEFAULT_VALUE_STRING);
						if (StringUtils.notBlank(paramName)) {
							if (StringUtils.isEmpty(paramValue)) {
								throw new ServiceException(0x0000000F0001L);
							}
							String pathKey = "{" + paramName + "}";
							if (servicePath.indexOf(pathKey) > 0) {
								servicePath = StringUtils.replace(servicePath, pathKey,
										URLEncoder.encode(paramValue, Globals.DEFAULT_ENCODING));
							}
						}
					}

					if (Arrays.stream(annotations[i])
							.anyMatch(annotation -> annotation.annotationType().equals(HeaderParam.class))) {
						String paramName =
								Arrays.stream(annotations[i]).filter(annotation ->
												annotation.annotationType().equals(HeaderParam.class))
										.findFirst()
										.map(annotation -> ((HeaderParam) annotation).value())
										.orElse(Globals.DEFAULT_VALUE_STRING);
						if (StringUtils.notBlank(paramName)) {
							this.headerMap.put(paramName, paramValue);
						}
					}
				}
			}

			Form form = null;
			if (HttpMethodOption.POST.equals(methodOption)
					|| HttpMethodOption.PUT.equals(methodOption)
					|| HttpMethodOption.PATCH.equals(methodOption)) {
				form = new Form();
				formParameters.forEach(form::param);
			}

			try (Client client = this.clientBuilder.build()) {
				WebTarget webTarget = client.target(servicePath);
				queryParameters.forEach(webTarget::queryParam);
				matrixParameters.forEach(webTarget::matrixParam);
				String[] acceptTypes = method.isAnnotationPresent(Produces.class)
						? method.getAnnotation(Produces.class).value()
						: new String[]{"*/*"};
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Accept data types: {}", String.join(",", acceptTypes));
				}
				Invocation.Builder builder = webTarget.request(acceptTypes);
				if (method.isAnnotationPresent(Consumes.class)) {
					builder.accept(method.getAnnotation(Consumes.class).value());
				}
				this.headerMap.forEach(builder::header);
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Service request path: {}", servicePath);
					LOGGER.debug("Request headers: {}",
							StringUtils.objectToString(this.headerMap, StringUtils.StringType.JSON, Boolean.TRUE));
					LOGGER.debug("Request parameters: {}",
							StringUtils.objectToString(queryParameters, StringUtils.StringType.JSON, Boolean.TRUE));
					LOGGER.debug("Request matrix parameters: {}",
							StringUtils.objectToString(matrixParameters, StringUtils.StringType.JSON, Boolean.TRUE));
				}
				return this.execute(methodOption, builder, form, method);
			}
		}

		/**
		 * <h3 class="en-US">Send request and initialize response instance</h3>
		 * <h3 class="zh-CN">发送请求并初始化响应实例对象</h3>
		 *
		 * @param methodOption <span class="en-US">HTTP method option Enumerations</span>
		 *                     <span class="zh-CN">HTTP请求方法枚举</span>
		 * @param builder      <span class="en-US">Request builder</span>
		 *                     <span class="zh-CN">请求构建器</span>
		 * @param form         <span class="en-US">Form information instance</span>
		 *                     <span class="zh-CN">表单信息实例对象</span>
		 * @return <span class="en-US">initialized response instance</span>
		 * <span class="zh-CN">初始化的响应实例对象</span>
		 * @throws ServiceException <span class="en-US">If http method not supported</span>
		 *                          <span class="zh-CN">如果HTTP请求方法不支持</span>
		 */
		private Response initResponse(final HttpMethodOption methodOption, final Invocation.Builder builder,
		                              final Form form) throws ServiceException {
			switch (methodOption) {
				case GET:
					return builder.get();
				case PATCH:
					return builder.method("PATCH",
							Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
				case PUT:
					return builder.put(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
				case POST:
					return builder.post(Entity.entity(form, MediaType.APPLICATION_FORM_URLENCODED_TYPE));
				case DELETE:
					return builder.delete();
				case HEAD:
					return builder.head();
				default:
					throw new ServiceException(0x0000000F0002L, methodOption.toString());
			}
		}

		/**
		 * <h3 class="en-US">Send request and parse response information</h3>
		 * <h3 class="zh-CN">发送请求并解析响应信息</h3>
		 *
		 * @param methodOption <span class="en-US">HTTP method option Enumerations</span>
		 *                     <span class="zh-CN">HTTP请求方法枚举</span>
		 * @param builder      <span class="en-US">Request builder</span>
		 *                     <span class="zh-CN">请求构建器</span>
		 * @param form         <span class="en-US">Form information instance</span>
		 *                     <span class="zh-CN">表单信息实例对象</span>
		 * @param method       <span class="en-US">Invoke method instance</span>
		 *                     <span class="zh-CN">调用方法的实例对象</span>
		 * @return <span class="en-US">Parsed response information</span>
		 * <span class="zh-CN">解析的响应信息</span>
		 * @throws ServiceException <span class="en-US">If http method not supported, or an error occurs when send request or parse response information</span>
		 *                          <span class="zh-CN">如果HTTP请求方法不支持，发送请求或解析响应信息时出现异常</span>
		 */
		private Object execute(final HttpMethodOption methodOption, final Invocation.Builder builder,
		                       final Form form, final Method method) throws ServiceException {
			try (Response response = this.initResponse(methodOption, builder, form)) {
				boolean operateResult;
				switch (methodOption) {
					case PUT:
						operateResult = (response.getStatus() == HttpServletResponse.SC_CREATED
								|| response.getStatus() == HttpServletResponse.SC_NO_CONTENT
								|| response.getStatus() == HttpServletResponse.SC_OK);
						break;
					case POST:
						operateResult = (response.getStatus() == HttpServletResponse.SC_CREATED
								|| response.getStatus() == HttpServletResponse.SC_OK);
						break;
					case PATCH:
					case DELETE:
						operateResult = (response.getStatus() == HttpServletResponse.SC_NO_CONTENT);
						break;
					default:
						operateResult = (response.getStatus() == HttpServletResponse.SC_OK);
						break;
				}

				if (operateResult) {
					if (response.getStatus() == HttpServletResponse.SC_NO_CONTENT) {
						return null;
					}

					Class<?> returnType = method.getReturnType();
					if (void.class.equals(returnType)) {
						return null;
					}
					String contentType = response.getHeaderString("Content-Type");
					String charsetEncoding =
							Arrays.stream(StringUtils.tokenizeToStringArray(contentType, ";"))
									.filter(string -> string.trim().toLowerCase().startsWith("charset="))
									.findFirst()
									.map(string -> string.substring("charset=".length()))
									.orElse(Globals.DEFAULT_ENCODING);

					Class<?> paramClass = ClassUtils.componentType(method.getReturnType());

					String responseData = response.readEntity(String.class);
					if (responseData.endsWith(FileUtils.CRLF)) {
						responseData = responseData.substring(0, responseData.length() - FileUtils.CRLF.length());
					}
					if (responseData.endsWith(Character.toString(FileUtils.CR))) {
						responseData = responseData.substring(0, responseData.length() - Character.toString(FileUtils.CR).length());
					}
					if (responseData.endsWith(Character.toString(FileUtils.LF))) {
						responseData = responseData.substring(0, responseData.length() - Character.toString(FileUtils.LF).length());
					}

					if (returnType.isArray()) {
						return Optional.ofNullable(StringUtils.stringToList(responseData, charsetEncoding, paramClass))
								.map(List::toArray)
								.orElse(new ArrayList<>().toArray());
					} else if (List.class.isAssignableFrom(returnType)) {
						return Optional.ofNullable(StringUtils.stringToList(responseData, charsetEncoding, paramClass))
								.orElse(new ArrayList<>());
					}
					switch (response.getHeaderString(HttpHeaders.CONTENT_TYPE)) {
						case FileUtils.MIME_TYPE_JSON:
							return StringUtils.stringToObject(responseData, StringUtils.StringType.JSON, returnType);
						case FileUtils.MIME_TYPE_TEXT_XML:
						case FileUtils.MIME_TYPE_XML:
							return StringUtils.stringToObject(responseData, StringUtils.StringType.XML, returnType);
						case FileUtils.MIME_TYPE_TEXT_YAML:
						case FileUtils.MIME_TYPE_YAML:
							return StringUtils.stringToObject(responseData, StringUtils.StringType.YAML, returnType);
						default:
							return responseData;
					}
				} else {
					String errorMsg = response.readEntity(String.class);
					if (LOGGER.isDebugEnabled()) {
						if (response.getStatus() == HttpServletResponse.SC_BAD_REQUEST) {
							errorMsg += "Send request data error!";
						} else if (HttpMethodOption.GET.equals(methodOption)
								&& response.getStatus() == HttpServletResponse.SC_NOT_FOUND) {
							errorMsg += "Not found data! ";
						} else if (response.getStatus() == HttpServletResponse.SC_UNAUTHORIZED) {
							errorMsg += "Unauthenticated error! ";
						} else if (response.getStatus() == HttpServletResponse.SC_FORBIDDEN) {
							errorMsg += "Request forbidden! ";
						} else if (response.getStatus() == HttpServletResponse.SC_BAD_GATEWAY
								|| response.getStatus() == HttpServletResponse.SC_SERVICE_UNAVAILABLE
								|| response.getStatus() == HttpServletResponse.SC_GATEWAY_TIMEOUT) {
							errorMsg += "Request forbidden! ";
						} else {
							errorMsg += Globals.DEFAULT_VALUE_STRING;
						}
						LOGGER.debug("Response_Message_Debug", response.getStatus(), errorMsg);
					}
					throw new ServiceException(0x0000000F0003L, errorMsg);
				}
			} catch (Exception e) {
				if (e instanceof ServiceException) {
					throw e;
				}
				throw new ServiceException(0x0000000F0003L, e);
			}
		}
	}

	/**
	 * <h2 class="en-US">JavaBean parameter define</h2>
	 * <h2 class="zh-CN">JavaBean参数定义</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2020 16:33:27 $
	 */
	private static final class BeanParameter {
		/**
		 * <span class="en-US">Form parameter map</span>
		 * <span class="zh-CN">表单信息映射</span>
		 */
		final Map<String, String> formParameters = new HashMap<>();
		/**
		 * <span class="en-US">Query parameter map</span>
		 * <span class="zh-CN">查询信息映射</span>
		 */
		final Map<String, String> queryParameters = new HashMap<>();
		/**
		 * <span class="en-US">Matrix parameter map</span>
		 * <span class="zh-CN">矩阵信息映射</span>
		 */
		final Map<String, String[]> matrixParameters = new HashMap<>();
		/**
		 * <span class="en-US">Header parameter map</span>
		 * <span class="zh-CN">请求头信息映射</span>
		 */
		final Map<String, String> headers = new HashMap<>();
		/**
		 * <span class="en-US">Path parameter map</span>
		 * <span class="zh-CN">请求路径信息映射</span>
		 */
		final Map<String, String> paths = new HashMap<>();

		/**
		 * <h3 class="en-US">Constructor for BeanParameter</h3>
		 * <h3 class="zh-CN">BeanParameter的构造方法</h3>
		 *
		 * @param beanObject     <span class="en-US">JavaBean parameter instance</span>
		 *                       <span class="zh-CN">JavaBean参数信息实例对象</span>
		 * @param mediaTypes     <span class="en-US">Request media types array</span>
		 *                       <span class="zh-CN">请求数据类型数组</span>
		 * @param transferConfig <span class="en-US">Data transfer configure</span>
		 *                       <span class="zh-CN">数据转换配置信息</span>
		 */
		BeanParameter(final Object beanObject, final String[] mediaTypes,
		              final TransferConfig transferConfig) {
			ReflectionUtils.getAllDeclaredFields(beanObject.getClass(), Boolean.TRUE).forEach(field -> {
				Object fieldValue = ReflectionUtils.getFieldValue(field, beanObject);
				if (field.isAnnotationPresent(BeanParam.class)) {
					BeanParameter beanParameter = new BeanParameter(fieldValue, mediaTypes, transferConfig);
					this.formParameters.putAll(beanParameter.getFormParameters());
					this.queryParameters.putAll(beanParameter.getQueryParameters());
					this.matrixParameters.putAll(beanParameter.getMatrixParameters());
					this.headers.putAll(beanParameter.getHeaders());
					this.paths.putAll(beanParameter.getPaths());
				} else {
					String stringValue = transferConfig.marshal(fieldValue);
					if (field.isAnnotationPresent(QueryParam.class)) {
						this.queryParameters.put(field.getAnnotation(QueryParam.class).value(), stringValue);
					} else if (field.isAnnotationPresent(FormParam.class)) {
						this.formParameters.put(field.getAnnotation(FormParam.class).value(), stringValue);
					} else if (field.isAnnotationPresent(MatrixParam.class)) {
						String paramName = field.getAnnotation(MatrixParam.class).value();
						String[] paramValues = this.matrixParameters.getOrDefault(paramName, new String[0]);
						this.matrixParameters.put(paramName, appendValue(paramValues, stringValue));
					} else if (field.isAnnotationPresent(HeaderParam.class)) {
						this.headers.put(field.getAnnotation(HeaderParam.class).value(), stringValue);
					} else if (field.isAnnotationPresent(PathParam.class)) {
						this.paths.put(field.getAnnotation(HeaderParam.class).value(), stringValue);
					}
				}
			});
		}

		/**
		 * <h3 class="en-US">Getter method for form parameter map</h3>
		 * <h3 class="zh-CN">表单信息映射的Getter方法</h3>
		 *
		 * @return <span class="en-US">Form parameter map</span>
		 * <span class="zh-CN">表单信息映射</span>
		 */
		public Map<String, String> getFormParameters() {
			return formParameters;
		}

		/**
		 * <h3 class="en-US">Getter method for query parameter map</h3>
		 * <h3 class="zh-CN">查询信息映射的Getter方法</h3>
		 *
		 * @return <span class="en-US">Query parameter map</span>
		 * <span class="zh-CN">查询信息映射</span>
		 */
		public Map<String, String> getQueryParameters() {
			return queryParameters;
		}

		/**
		 * <h3 class="en-US">Getter method for matrix parameter map</h3>
		 * <h3 class="zh-CN">矩阵信息映射的Getter方法</h3>
		 *
		 * @return <span class="en-US">Matrix parameter map</span>
		 * <span class="zh-CN">矩阵信息映射</span>
		 */
		public Map<String, String[]> getMatrixParameters() {
			return matrixParameters;
		}

		/**
		 * <h3 class="en-US">Getter method for header parameter map</h3>
		 * <h3 class="zh-CN">请求头信息映射的Getter方法</h3>
		 *
		 * @return <span class="en-US">Header parameter map</span>
		 * <span class="zh-CN">请求头信息映射</span>
		 */
		public Map<String, String> getHeaders() {
			return headers;
		}

		/**
		 * <h3 class="en-US">Getter method for path parameter map</h3>
		 * <h3 class="zh-CN">请求路径信息映射的Getter方法</h3>
		 *
		 * @return <span class="en-US">Path parameter map</span>
		 * <span class="zh-CN">请求路径信息映射</span>
		 */
		public Map<String, String> getPaths() {
			return paths;
		}
	}
}
