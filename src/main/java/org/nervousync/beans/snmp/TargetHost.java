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
package org.nervousync.beans.snmp;

import java.io.Serializable;

import org.nervousync.enumerations.net.IPProtocol;
import org.nervousync.enumerations.snmp.SNMPVersion;
import org.nervousync.enumerations.snmp.auth.SNMPAuthProtocol;
import org.nervousync.enumerations.snmp.auth.SNMPAuthType;
import org.nervousync.enumerations.snmp.auth.SNMPPrivProtocol;

/**
 * <h2 class="en-US">SNMP Target Host Define</h2>
 * <h2 class="zh-CN">SNMP目标主机定义</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.2 $ $Date: Sep 25, 2022 21:47:36 $
 */
public final class TargetHost implements Serializable {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = -7043141633658888918L;
	/**
	 * <span class="en-US">Default port number of SNMP</span>
	 * <span class="zh-CN">默认的SNMP端口号</span>
	 */
	private static final int DEFAULT_SNMP_PORT = 161;
	/**
	 * <span class="en-US">IP Protocol</span>
	 * <span class="zh-CN">IP协议</span>
	 */
	private final IPProtocol protocol;
	/**
	 * <span class="en-US">Target Host IP Address</span>
	 * <span class="zh-CN">目标主机IP地址</span>
	 */
	private final String ipAddress;
	/**
	 * <span class="en-US">Target Host Community String</span>
	 * <span class="zh-CN">目标主机的查询密码</span>
	 */
	private final String community;
	/**
	 * <span class="en-US">Target Host Port Number</span>
	 * <span class="zh-CN">目标主机端口号</span>
	 */
	private final int port;
	/**
	 * <span class="en-US">Request Retry Limit Times</span>
	 * <span class="zh-CN">请求失败重试次数</span>
	 */
	private final int retries;
	/**
	 * <span class="en-US">Request Timeout</span>
	 * <span class="zh-CN">请求超时时间</span>
	 */
	private final long timeOut;
	/**
	 * <span class="en-US">SNMP Authentication Type</span>
	 * <span class="zh-CN">SNMP验证类型</span>
	 */
	private SNMPAuthType auth = SNMPAuthType.NOAUTH_NOPRIV;
	/**
	 * <span class="en-US">SNMP Authentication Protocol</span>
	 * <span class="zh-CN">SNMP验证协议</span>
	 */
	private SNMPAuthProtocol authProtocol = null;
	/**
	 * <span class="en-US">SNMP Authentication Password</span>
	 * <span class="zh-CN">SNMP验证密码</span>
	 */
	private String authPassword = null;
	/**
	 * <span class="en-US">Type of encryption for the privacy password if authentication level is AUTH_PRIV</span>
	 * <span class="zh-CN">私有密码的加密方式，当验证类型为AUTH_PRIV时有效</span>
	 */
	private SNMPPrivProtocol privProtocol = null;
	/**
	 * <span class="en-US">SNMP Private Password. The minimum length of the Priv Password must be eight characters.</span>
	 * <span class="zh-CN">SNMP私有密码。密码长度必须大于等于8个字符</span>
	 */
	private String privPassword = null;
	/**
	 * <span class="en-US">Target Host SNMP Version. Default: 2c</span>
	 * <span class="zh-CN">目标主机SNMP版本号。默认：2c</span>
	 */
	private SNMPVersion version = SNMPVersion.VERSION2C;

	/**
	 * <h3 class="en-US">Private constructor for TargetHost</h3>
	 * <h3 class="zh-CN">TargetHost的私有构造函数</h3>
	 *
	 * @param protocol  <span class="en-US">IP Protocol</span>
	 *                  <span class="zh-CN">IP协议</span>
	 * @param ipAddress <span class="en-US">Target Host IP Address</span>
	 *                  <span class="zh-CN">目标主机IP地址</span>
	 * @param community <span class="en-US">Target Host Community String</span>
	 *                  <span class="zh-CN">目标主机的查询密码</span>
	 * @param port      <span class="en-US">Target Host Port Number</span>
	 *                  <span class="zh-CN">目标主机端口号</span>
	 * @param retries   <span class="en-US">Request Retry Limit Times</span>
	 *                  <span class="zh-CN">请求失败重试次数</span>
	 * @param timeOut   <span class="en-US">Request Timeout</span>
	 *                  <span class="zh-CN">请求超时时间</span>
	 */
	private TargetHost(final IPProtocol protocol, final String ipAddress, final String community,
	                   final int port, final int retries, final long timeOut) {
		this.protocol = protocol;
		this.ipAddress = ipAddress;
		this.community = community;
		this.port = port <= 0 ? DEFAULT_SNMP_PORT : port;
		this.retries = retries <= 0 ? 1 : retries;
		this.timeOut = timeOut <= 0L ? 1000L : timeOut;
	}

	/**
	 * <h3 class="en-US">Static method for create TargetHost instance of localhost</h3>
	 * <span class="en-US">Using default community string: "public", default port number: 161, retry time: 1, default timeout: 1000</span>
	 * <h3 class="zh-CN">静态方法用于创建本地主机的TargetHost实例对象</h3>
	 * <span class="en-US">使用默认的查询密码："public"，默认的端口号：161，默认重试次数：1，默认超时时间：1000</span>
	 *
	 * @param protocol <span class="en-US">IP Protocol</span>
	 *                 <span class="zh-CN">IP协议</span>
	 * @return        <span class="en-US">Generated TargetHost instance</span>
	 * <span class="zh-CN">生成的TargetHost实例对象</span>
	 */
	public static TargetHost local(final IPProtocol protocol) {
		return local(protocol, "public", DEFAULT_SNMP_PORT, 1, 1000L);
	}

	/**
	 * <h3 class="en-US">Static method for create TargetHost instance of localhost</h3>
	 * <span class="en-US">Using given community string, default port number: 161, retry time: 1, default timeout: 1000</span>
	 * <h3 class="zh-CN">静态方法用于创建本地主机的TargetHost实例对象</h3>
	 * <span class="en-US">使用给定的查询密码，默认的端口号：161，默认重试次数：1，默认超时时间：1000</span>
	 *
	 * @param protocol  <span class="en-US">IP Protocol</span>
	 *                  <span class="zh-CN">IP协议</span>
	 * @param community <span class="en-US">Target Host Community String</span>
	 *                  <span class="zh-CN">目标主机的查询密码</span>
	 * @return        <span class="en-US">Generated TargetHost instance</span>
	 * <span class="zh-CN">生成的TargetHost实例对象</span>
	 */
	public static TargetHost local(final IPProtocol protocol, final String community) {
		return local(protocol, community, DEFAULT_SNMP_PORT, 1, 1000L);
	}

	/**
	 * <h3 class="en-US">Static method for create TargetHost instance of localhost</h3>
	 * <span class="en-US">Using given community string and port number, retry time: 1, default timeout: 1000</span>
	 * <h3 class="zh-CN">静态方法用于创建本地主机的TargetHost实例对象</h3>
	 * <span class="en-US">使用给定的查询密码和端口号，默认重试次数：1，默认超时时间：1000</span>
	 *
	 * @param protocol  <span class="en-US">IP Protocol</span>
	 *                  <span class="zh-CN">IP协议</span>
	 * @param community <span class="en-US">Target Host Community String</span>
	 *                  <span class="zh-CN">目标主机的查询密码</span>
	 * @param port      <span class="en-US">Target Host Port Number</span>
	 *                  <span class="zh-CN">目标主机端口号</span>
	 * @return        <span class="en-US">Generated TargetHost instance</span>
	 * <span class="zh-CN">生成的TargetHost实例对象</span>
	 */
	public static TargetHost local(final IPProtocol protocol, final String community, final int port) {
		return local(protocol, community, port, 1, 1000L);
	}

	/**
	 * <h3 class="en-US">Static method for create TargetHost instance of localhost</h3>
	 * <span class="en-US">Using given community string and port number, retry times and timeout value</span>
	 * <h3 class="zh-CN">静态方法用于创建本地主机的TargetHost实例对象</h3>
	 * <span class="en-US">使用给定的查询密码和端口号，重试次数以及超时时间</span>
	 *
	 * @param protocol  <span class="en-US">IP Protocol</span>
	 *                  <span class="zh-CN">IP协议</span>
	 * @param community <span class="en-US">Target Host Community String</span>
	 *                  <span class="zh-CN">目标主机的查询密码</span>
	 * @param port      <span class="en-US">Target Host Port Number</span>
	 *                  <span class="zh-CN">目标主机端口号</span>
	 * @param retries   <span class="en-US">Request Retry Limit Times</span>
	 *                  <span class="zh-CN">请求失败重试次数</span>
	 * @param timeOut   <span class="en-US">Request Timeout</span>
	 *                  <span class="zh-CN">请求超时时间</span>
	 * @return        <span class="en-US">Generated TargetHost instance</span>
	 * <span class="zh-CN">生成的TargetHost实例对象</span>
	 */
	public static TargetHost local(final IPProtocol protocol, final String community, final int port,
	                               final int retries, final long timeOut) {
		return new TargetHost(protocol, "127.0.0.1", community, port, retries, timeOut);
	}

	/**
	 * <h3 class="en-US">Static method for create TargetHost instance of remote host address</h3>
	 * <span class="en-US">Using default community string: "public", default port number: 161, retry time: 1, default timeout: 1000</span>
	 * <h3 class="zh-CN">静态方法用于创建目标主机的TargetHost实例对象</h3>
	 * <span class="en-US">使用默认的查询密码："public"，默认的端口号：161，默认重试次数：1，默认超时时间：1000</span>
	 *
	 * @param protocol  <span class="en-US">IP Protocol</span>
	 *                  <span class="zh-CN">IP协议</span>
	 * @param ipAddress <span class="en-US">Target Host IP Address</span>
	 *                  <span class="zh-CN">目标主机IP地址</span>
	 * @return        <span class="en-US">Generated TargetHost instance</span>
	 * <span class="zh-CN">生成的TargetHost实例对象</span>
	 */
	public static TargetHost remote(final IPProtocol protocol, final String ipAddress) {
		return remote(protocol, ipAddress, "public");
	}

	/**
	 * <h3 class="en-US">Static method for create TargetHost instance of remote host address</h3>
	 * <span class="en-US">Using given community string, default port number: 161, retry time: 1, default timeout: 1000</span>
	 * <h3 class="zh-CN">静态方法用于创建目标主机的TargetHost实例对象</h3>
	 * <span class="en-US">使用给定的查询密码，默认的端口号：161，默认重试次数：1，默认超时时间：1000</span>
	 *
	 * @param protocol  <span class="en-US">IP Protocol</span>
	 *                  <span class="zh-CN">IP协议</span>
	 * @param ipAddress <span class="en-US">Target Host IP Address</span>
	 *                  <span class="zh-CN">目标主机IP地址</span>
	 * @param community <span class="en-US">Target Host Community String</span>
	 *                  <span class="zh-CN">目标主机的查询密码</span>
	 * @return        <span class="en-US">Generated TargetHost instance</span>
	 * <span class="zh-CN">生成的TargetHost实例对象</span>
	 */
	public static TargetHost remote(final IPProtocol protocol, final String ipAddress, final String community) {
		return remote(protocol, ipAddress, community, DEFAULT_SNMP_PORT, 1, 1000L);
	}

	/**
	 * <h3 class="en-US">Static method for create TargetHost instance of remote host address</h3>
	 * <span class="en-US">Using given community string and port number, retry time: 1, default timeout: 1000</span>
	 * <h3 class="zh-CN">静态方法用于创建目标主机的TargetHost实例对象</h3>
	 * <span class="en-US">使用给定的查询密码和端口号，默认重试次数：1，默认超时时间：1000</span>
	 *
	 * @param protocol  <span class="en-US">IP Protocol</span>
	 *                  <span class="zh-CN">IP协议</span>
	 * @param ipAddress <span class="en-US">Target Host IP Address</span>
	 *                  <span class="zh-CN">目标主机IP地址</span>
	 * @param community <span class="en-US">Target Host Community String</span>
	 *                  <span class="zh-CN">目标主机的查询密码</span>
	 * @param port      <span class="en-US">Target Host Port Number</span>
	 *                  <span class="zh-CN">目标主机端口号</span>
	 * @return        <span class="en-US">Generated TargetHost instance</span>
	 * <span class="zh-CN">生成的TargetHost实例对象</span>
	 */
	public static TargetHost remote(final IPProtocol protocol, final String ipAddress, final String community, final int port) {
		return remote(protocol, ipAddress, community, port, 1, 1000L);
	}

	/**
	 * <h3 class="en-US">Static method for create TargetHost instance of remote host address</h3>
	 * <span class="en-US">Using given community string and port number, retry times and timeout value</span>
	 * <h3 class="zh-CN">静态方法用于创建目标主机的TargetHost实例对象</h3>
	 * <span class="en-US">使用给定的查询密码和端口号，重试次数以及超时时间</span>
	 *
	 * @param protocol  <span class="en-US">IP Protocol</span>
	 *                  <span class="zh-CN">IP协议</span>
	 * @param ipAddress <span class="en-US">Target Host IP Address</span>
	 *                  <span class="zh-CN">目标主机IP地址</span>
	 * @param community <span class="en-US">Target Host Community String</span>
	 *                  <span class="zh-CN">目标主机的查询密码</span>
	 * @param port      <span class="en-US">Target Host Port Number</span>
	 *                  <span class="zh-CN">目标主机端口号</span>
	 * @param retries   <span class="en-US">Request Retry Limit Times</span>
	 *                  <span class="zh-CN">请求失败重试次数</span>
	 * @param timeOut   <span class="en-US">Request Timeout</span>
	 *                  <span class="zh-CN">请求超时时间</span>
	 * @return <span class="en-US">Generated TargetHost instance</span>
	 * <span class="zh-CN">生成的TargetHost实例对象</span>
	 */
	public static TargetHost remote(final IPProtocol protocol, final String ipAddress, final String community,
	                                final int port, final int retries, final long timeOut) {
		return new TargetHost(protocol, ipAddress, community, port, retries, timeOut);
	}

	/**
	 * <h3 class="en-US">Getter method for IP Protocol</h3>
	 * <h3 class="zh-CN">IP协议的Getter方法</h3>
	 *
	 * @return <span class="en-US">IP Protocol</span>
	 * <span class="zh-CN">IP协议</span>
	 */
	public IPProtocol getProtocol() {
		return protocol;
	}

	/**
	 * <h3 class="en-US">Getter method for target host ip address</h3>
	 * <h3 class="zh-CN">目标主机IP地址的Getter方法</h3>
	 *
	 * @return <span class="en-US">Target Host IP Address</span>
	 * <span class="zh-CN">目标主机IP地址</span>
	 */
	public String getIpAddress() {
		return ipAddress;
	}

	/**
	 * <h3 class="en-US">Getter method for community string</h3>
	 * <h3 class="zh-CN">查询密码的Getter方法</h3>
	 *
	 * @return <span class="en-US">Target Host Community String</span>
	 * <span class="zh-CN">目标主机的查询密码</span>
	 */
	public String getCommunity() {
		return community;
	}

	/**
	 * <h3 class="en-US">Getter method for authentication type</h3>
	 * <h3 class="zh-CN">身份验证方式的Getter方法</h3>
	 *
	 * @return <span class="en-US">SNMP Authentication Type</span>
	 * <span class="zh-CN">SNMP验证类型</span>
	 */
	public SNMPAuthType getAuth() {
		return auth;
	}

	/**
	 * <h3 class="en-US">Getter method for authentication protocol</h3>
	 * <h3 class="zh-CN">身份验证协议的Getter方法</h3>
	 *
	 * @return <span class="en-US">SNMP Authentication Protocol</span>
	 * <span class="zh-CN">SNMP验证协议</span>
	 */
	public SNMPAuthProtocol getAuthProtocol() {
		return authProtocol;
	}

	/**
	 * <h3 class="en-US">Getter method for authentication password</h3>
	 * <h3 class="zh-CN">身份验证密码的Getter方法</h3>
	 *
	 * @return <span class="en-US">SNMP Authentication Password</span>
	 * <span class="zh-CN">SNMP验证密码</span>
	 */
	public String getAuthPassword() {
		return authPassword;
	}

	/**
	 * <h3 class="en-US">Getter method for type of encryption for the privacy password</h3>
	 * <h3 class="zh-CN">私有密码加密方式的Getter方法</h3>
	 *
	 * @return <span class="en-US">Type of encryption for the privacy password if authentication level is AUTH_PRIV</span>
	 * <span class="zh-CN">私有密码的加密方式，当验证类型为AUTH_PRIV时有效</span>
	 */
	public SNMPPrivProtocol getPrivProtocol() {
		return privProtocol;
	}

	/**
	 * <h3 class="en-US">Getter method for SNMP Private Password</h3>
	 * <h3 class="zh-CN">SNMP私有密码的Getter方法</h3>
	 *
	 * @return <span class="en-US">SNMP Private Password. The minimum length of the Priv Password must be eight characters.</span>
	 * <span class="zh-CN">SNMP私有密码。密码长度必须大于等于8个字符</span>
	 */
	public String getPrivPassword() {
		return privPassword;
	}

	/**
	 * <h3 class="en-US">Getter method for SNMP version</h3>
	 * <h3 class="zh-CN">SNMP版本号的Getter方法</h3>
	 *
	 * @return <span class="en-US">Target Host SNMP Version. Default: 2c</span>
	 * <span class="zh-CN">目标主机SNMP版本号。默认：2c</span>
	 */
	public SNMPVersion getVersion() {
		return version;
	}

	/**
	 * <h3 class="en-US">Setter method for SNMP version</h3>
	 * <h3 class="zh-CN">SNMP版本号的Setter方法</h3>
	 *
	 * @param version <span class="en-US">Target Host SNMP Version.</span>
	 *                <span class="zh-CN">目标主机SNMP版本号。</span>
	 */
	public void setVersion(final SNMPVersion version) {
		this.version = version;
	}

	/**
	 * <h3 class="en-US">Getter method for Target Host Port number</h3>
	 * <h3 class="zh-CN">目标主机端口号的Getter方法</h3>
	 *
	 * @return <span class="en-US">Target Host Port Number</span>
	 * <span class="zh-CN">目标主机端口号</span>
	 */
	public int getPort() {
		return port;
	}

	/**
	 * <h3 class="en-US">Getter method for retry limit times</h3>
	 * <h3 class="zh-CN">重试次数的Getter方法</h3>
	 *
	 * @return <span class="en-US">Request Retry Limit Times</span>
	 * <span class="zh-CN">请求失败重试次数</span>
	 */
	public int getRetries() {
		return retries;
	}

	/**
	 * <h3 class="en-US">Getter method for request timeout</h3>
	 * <h3 class="zh-CN">请求超时时间的Getter方法</h3>
	 *
	 * @return <span class="en-US">Request Timeout</span>
	 * <span class="zh-CN">请求超时时间</span>
	 */
	public long getTimeOut() {
		return timeOut;
	}

	/**
	 * <h3 class="en-US">Configure authentication information using authentication type: SNMPAuthType.AUTH_NOPRIV</h3>
	 * <h3 class="zh-CN">设置身份验证信息，使用身份验证类型为：SNMPAuthType.AUTH_NOPRIV</h3>
	 *
	 * @param authProtocol <span class="en-US">SNMP Authentication Type</span>
	 *                     <span class="zh-CN">SNMP验证类型</span>
	 * @param authPassword <span class="en-US">SNMP Authentication Password</span>
	 *                     <span class="zh-CN">SNMP验证密码</span>
	 * @see org.nervousync.enumerations.snmp.auth.SNMPAuthProtocol
	 */
	public void authNoPriv(final SNMPAuthProtocol authProtocol, final String authPassword) {
		this.auth = SNMPAuthType.AUTH_NOPRIV;
		this.authProtocol = authProtocol;
		this.authPassword = authPassword;
	}

	/**
	 * <h3 class="en-US">Configure authentication information using authentication type: SNMPAuthType.AUTH_PRIV</h3>
	 * <h3 class="zh-CN">设置身份验证信息，使用身份验证类型为：SNMPAuthType.AUTH_PRIV</h3>
	 *
	 * @param authProtocol <span class="en-US">SNMP Authentication Type</span>
	 *                     <span class="zh-CN">SNMP验证类型</span>
	 * @param authPassword <span class="en-US">SNMP Authentication Password</span>
	 *                     <span class="zh-CN">SNMP验证密码</span>
	 * @param privProtocol <span class="en-US">Type of encryption for the privacy password if authentication level is AUTH_PRIV</span>
	 *                     <span class="zh-CN">私有密码的加密方式，当验证类型为AUTH_PRIV时有效</span>
	 * @param privPassword <span class="en-US">SNMP Private Password. The minimum length of the Priv Password must be eight characters.</span>
	 *                     <span class="zh-CN">SNMP私有密码。密码长度必须大于等于8个字符</span>
	 * @see org.nervousync.enumerations.snmp.auth.SNMPAuthProtocol
	 * @see org.nervousync.enumerations.snmp.auth.SNMPPrivProtocol
	 */
	public void authWithPriv(final SNMPAuthProtocol authProtocol, final String authPassword,
	                         final SNMPPrivProtocol privProtocol, final String privPassword) {
		this.auth = SNMPAuthType.AUTH_PRIV;
		this.authProtocol = authProtocol;
		this.authPassword = authPassword;
		this.privProtocol = privProtocol;
		this.privPassword = privPassword;
	}
}
