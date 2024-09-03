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
package org.nervousync.beans.network;

import java.io.Serializable;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;

import jakarta.annotation.Nonnull;
import org.nervousync.exceptions.beans.network.NetworkInfoException;
import org.nervousync.utils.IPUtils;

/**
 * <h2 class="en-US">System NetworkInterface information define</h2>
 * <h2 class="zh-CN">系统网卡信息定义</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.3 $ $Date: Apr 06, 2020 11:53:10 $
 */
public final class NetworkInfo implements Serializable {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = -8060054814830700945L;
	/**
	 * <span class="en-US">Current network interface is virtual interface</span>
	 * <span class="zh-CN">当前网络接口是虚拟接口</span>
	 */
	private final boolean virtual;
	/**
	 * <span class="en-US">Display name of current network interface</span>
	 * <span class="zh-CN">当前网络接口的显示名称</span>
	 */
	private final String displayName;
	/**
	 * <span class="en-US">MAC address of current network interface</span>
	 * <span class="zh-CN">当前网络接口的物理地址</span>
	 */
	private String macAddress = "";
	/**
	 * <span class="en-US">IP address list of current network interface</span>
	 * <span class="zh-CN">当前网络接口绑定的IP地址列表</span>
	 */
	private final List<IPAddressInfo> ipAddressList = new ArrayList<>();

	/**
	 * <h2 class="en-US">Constructor for NetworkInfo</h2>
	 * <span class="en-US">Read network interface information from java.net.NetworkInterface instance</span>
	 * <h2 class="zh-CN">NetworkInfo的构造函数</h2>
	 * <span class="zh-CN">从java.net.NetworkInterface对象实例中读取网络接口相关信息</span>
	 *
	 * @param networkInterface <span class="en-US">Instance of java.net.NetworkInterface</span>
	 *                         <span class="zh-CN">java.net.NetworkInterface对象实例</span>
	 * @throws NetworkInfoException <span class="en-US">If the value of NetworkInterface is null or an I/O error occurs</span>
	 *                              <span class="zh-CN">当参数networkInterface为空或捕获I/O异常</span>
	 */
	public NetworkInfo(final NetworkInterface networkInterface) throws NetworkInfoException {
		if (networkInterface == null) {
			throw new NetworkInfoException(0x0000001A0001L, "Null_Network_Interface_Error");
		}
		try {
			if (networkInterface.isUp() && !networkInterface.isVirtual()) {
				byte[] macAddress = networkInterface.getHardwareAddress();
				if (macAddress != null && macAddress.length > 0) {
					StringBuilder stringBuilder = new StringBuilder();
					for (byte mac : macAddress) {
						stringBuilder.append(":");
						String address = Integer.toHexString(mac & 0xFF);
						if (address.length() == 1) {
							address = "0" + address;
						}
						stringBuilder.append(address.toUpperCase());
					}
					this.macAddress = stringBuilder.substring(1);
				}
			}
		} catch (SocketException e) {
			throw new NetworkInfoException(0x0000001A0002L, "Retrieve_Network_Interface_Error", e);
		}
		this.virtual = networkInterface.isVirtual();
		this.displayName = networkInterface.getDisplayName();
		Enumeration<InetAddress> enumeration = networkInterface.getInetAddresses();
		while (enumeration.hasMoreElements()) {
			Optional.ofNullable(enumeration.nextElement())
					.map(IPAddressInfo::new)
					.ifPresent(this.ipAddressList::add);
		}
	}

	/**
	 * <h3 class="en-US">Getter method for field virtual</h3>
	 * <h3 class="zh-CN">虚拟接口状态的Getter方法</h3>
	 *
	 * @return <span class="en-US">Virtual status</span>
	 * <span class="zh-CN">虚拟接口状态</span>
	 */
	public boolean isVirtual() {
		return virtual;
	}

	/**
	 * <h3 class="en-US">Getter method for display name</h3>
	 * <h3 class="zh-CN">显示名称的Getter方法</h3>
	 *
	 * @return <span class="en-US">Display name of current network interface</span>
	 * <span class="zh-CN">当前网络接口的显示名称</span>
	 */
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * <h3 class="en-US">Getter method for MAC address</h3>
	 * <h3 class="zh-CN">网卡物理地址的Getter方法</h3>
	 *
	 * @return <span class="en-US">MAC address of current network interface</span>
	 * <span class="zh-CN">当前网络接口的物理地址</span>
	 */
	public String getMacAddress() {
		return macAddress;
	}

	/**
	 * <h3 class="en-US">Getter method for IP address list</h3>
	 * <h3 class="zh-CN">网卡IP地址列表的Getter方法</h3>
	 *
	 * @return <span class="en-US">IP address list of current network interface</span>
	 * <span class="zh-CN">当前网络接口绑定的IP地址列表</span>
	 */
	public List<IPAddressInfo> getIpAddressList() {
		return ipAddressList;
	}

	/**
	 * <h3 class="en-US">Getter method for IPv4 address list</h3>
	 * <h3 class="zh-CN">网卡IPv4地址列表的Getter方法</h3>
	 *
	 * @return <span class="en-US">IPv4 address list of current network interface</span>
	 * <span class="zh-CN">当前网络接口绑定的IPv4地址列表</span>
	 */
	public List<IPAddressInfo> getIPv4AddressList() {
		List<IPAddressInfo> addressList = new ArrayList<>();
		for (IPAddressInfo ipAddressInfo : this.ipAddressList) {
			if (IPUtils.isIPv4Address(ipAddressInfo.getIpAddress())) {
				addressList.add(ipAddressInfo);
			}
		}
		return addressList;
	}

	/**
	 * <h3 class="en-US">Getter method for IPv6 address list</h3>
	 * <h3 class="zh-CN">网卡IPv6地址列表的Getter方法</h3>
	 *
	 * @return <span class="en-US">IPv6 address list of current network interface</span>
	 * <span class="zh-CN">当前网络接口绑定的IPv6地址列表</span>
	 */
	public List<IPAddressInfo> getIPv6AddressList() {
		List<IPAddressInfo> addressList = new ArrayList<>();
		for (IPAddressInfo ipAddressInfo : this.ipAddressList) {
			if (IPUtils.isIPv6Address(ipAddressInfo.getIpAddress())) {
				addressList.add(ipAddressInfo);
			}
		}
		return addressList;
	}

	/**
	 * <h3 class="en-US">IP address information define</h3>
	 * <h3 class="zh-CN">IP地址信息定义</h3>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0.0 $ $Date: Jul 2, 2018 09:22:28 $
	 */
	public static final class IPAddressInfo implements Serializable {
		/**
		 * <span class="en-US">Serial version UID</span>
		 * <span class="zh-CN">序列化UID</span>
		 */
		private static final long serialVersionUID = -2882813548945783456L;
		/**
		 * <span class="en-US">IP address string, supported IPv4 and IPv6</span>
		 * <span class="zh-CN">IP地址字符串，支持IPv4和IPv6</span>
		 */
		private final String ipAddress;
		/**
		 * <span class="en-US">SiteLocal address flag</span>
		 * <span class="zh-CN">私网地址标识</span>
		 */
		private final boolean local;
		/**
		 * <span class="en-US">Loop address flag</span>
		 * <span class="zh-CN">回环地址标识</span>
		 */
		private final boolean loop;
		/**
		 * <span class="en-US">LinkLocal address flag</span>
		 * <span class="zh-CN">链路地址标识</span>
		 */
		private final boolean linkLocal;

		/**
		 * <h2 class="en-US">Constructor for IPAddressInfo</h2>
		 * <span class="en-US">Read IP address information from java.net.InetAddress instance</span>
		 * <h2 class="zh-CN">IPAddressInfo的构造函数</h2>
		 * <span class="zh-CN">从java.net.InetAddress对象实例中读取IP地址相关信息</span>
		 *
		 * @param inetAddress <span class="en-US">Instance of java.net.InetAddress</span>
		 *                    <span class="zh-CN">java.net.InetAddress对象实例</span>
		 */
		public IPAddressInfo(@Nonnull final InetAddress inetAddress) {
			String ipAddress = inetAddress.getHostAddress();
			if (ipAddress.indexOf("%") > 0) {
				this.ipAddress = ipAddress.substring(0, ipAddress.indexOf("%"));
			} else {
				this.ipAddress = ipAddress;
			}
			this.local = inetAddress.isSiteLocalAddress();
			this.loop = inetAddress.isLoopbackAddress();
			this.linkLocal = inetAddress.isLinkLocalAddress();
		}

		/**
		 * <h3 class="en-US">Getter method for IP address string</h3>
		 * <h3 class="zh-CN">IP地址字符串的Getter方法</h3>
		 *
		 * @return <span class="en-US">IP address string, supported IPv4 and IPv6</span>
		 * <span class="zh-CN">IP地址字符串，支持IPv4和IPv6</span>
		 */
		public String getIpAddress() {
			return ipAddress;
		}

		/**
		 * <h3 class="en-US">Getter method for site local flag</h3>
		 * <h3 class="zh-CN">私网地址标识的Getter方法</h3>
		 *
		 * @return <span class="en-US">SiteLocal address flag</span>
		 * <span class="zh-CN">私网地址标识</span>
		 */
		public boolean isLocal() {
			return local;
		}

		/**
		 * <h3 class="en-US">Getter method for loop address flag</h3>
		 * <h3 class="zh-CN">回环地址标识的Getter方法</h3>
		 *
		 * @return <span class="en-US">Loop address flag</span>
		 * <span class="zh-CN">回环地址标识</span>
		 */
		public boolean isLoop() {
			return loop;
		}

		/**
		 * <h3 class="en-US">Getter method for link local flag</h3>
		 * <h3 class="zh-CN">链路地址标识的Getter方法</h3>
		 *
		 * @return <span class="en-US">LinkLocal address flag</span>
		 * <span class="zh-CN">链路地址标识</span>
		 */
		public boolean isLinkLocal() {
			return linkLocal;
		}
	}
}
