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

import org.nervousync.beans.snmp.SNMPData;
import org.nervousync.beans.snmp.TargetHost;
import org.nervousync.commons.Globals;
import org.nervousync.commons.snmp.SNMPDataOperator;
import org.nervousync.enumerations.net.IPProtocol;
import org.nervousync.enumerations.snmp.SNMPVersion;
import org.nervousync.enumerations.snmp.auth.SNMPAuthProtocol;
import org.nervousync.exceptions.snmp.ProcessorConfigException;
import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * <h2 class="en-US">SNMP utilities</h2>
 * <h2 class="zh-CN">SNMP工具集</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Oct 25, 2017 20:50:34 $
 */
public final class SNMPUtils {
	/**
	 * <span class="en-US">Singleton instance</span>
	 * <span class="zh-CN">单一实例对象</span>
	 */
	private static volatile SNMPUtils INSTANCE = null;
	/**
	 * <span class="en-US">Multilingual supported logger instance</span>
	 * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(SNMPUtils.class);
	/**
	 * <span class="en-US">Prefix string of UDP protocol</span>
	 * <span class="zh-CN">UDP协议前缀</span>
	 */
	private static final String PROTOCOL_UDP = "udp:";
	/**
	 * <span class="en-US">Prefix string of TCP protocol</span>
	 * <span class="zh-CN">TCP协议前缀</span>
	 */
	private static final String PROTOCOL_TCP = "tcp:";
	/**
	 * <span class="en-US">Schedule process period time (Unit: milliseconds)</span>
	 * <span class="zh-CN">调度处理的间隔时间（单位：毫秒）</span>
	 */
	private final long period;
	/**
	 * <span class="en-US">Registered target host list</span>
	 * <span class="zh-CN">注册的目标主机列表</span>
	 */
	private final List<TargetHost> existsHosts;
	/**
	 * <span class="en-US">Schedule processor</span>
	 * <span class="zh-CN">调度处理器</span>
	 */
	private final ScheduledExecutorService scheduledExecutorService;
	/**
	 * <span class="en-US">UDP agent</span>
	 * <span class="zh-CN">UDP客户端</span>
	 */
	private Snmp udpAgent;
	/**
	 * <span class="en-US">TCP agent</span>
	 * <span class="zh-CN">TCP客户端</span>
	 */
	private Snmp tcpAgent;

	/**
	 * <h3 class="en-US">Private constructor for SNMPUtils</h3>
	 * <h3 class="zh-CN">SNMP工具集的私有构造方法</h3>
	 *
	 * @param serverCount <span class="en-US">Maximum size of registered server list</span>
	 *                    <span class="zh-CN">允许注册目标主机的最大值</span>
	 * @param period      <span class="en-US">Schedule process period time (Unit: milliseconds)</span>
	 *                    <span class="zh-CN">调度处理的间隔时间（单位：毫秒）</span>
	 * @throws IOException <span class="en-US">If an error occurs when generate agent</span>
	 *                     <span class="zh-CN">当创建客户端时出现异常</span>
	 */
	private SNMPUtils(final int serverCount, final long period) throws IOException {
		this.period = Math.max(period, 1000L);
		this.existsHosts = new ArrayList<>(serverCount);
		this.scheduledExecutorService = Executors.newScheduledThreadPool(serverCount);
		this.udpAgent = new Snmp(new DefaultUdpTransportMapping());
		this.udpAgent.listen();
		this.tcpAgent = new Snmp(new DefaultTcpTransportMapping());
		this.tcpAgent.listen();
	}

	/**
	 * <h3 class="en-US">Initialize SNMP Utilities</h3>
	 * <h3 class="zh-CN">初始化SNMP工具集</h3>
	 *
	 * @param serverCount <span class="en-US">Maximum size of registered server list</span>
	 *                    <span class="zh-CN">允许注册目标主机的最大值</span>
	 * @return <span class="en-US">Initialize result</span>
	 * <span class="zh-CN">初始化结果</span>
	 */
	public static boolean initialize(final int serverCount) {
		return SNMPUtils.initialize(serverCount, Globals.DEFAULT_VALUE_LONG);
	}

	/**
	 * <h3 class="en-US">Initialize SNMP Utilities</h3>
	 * <h3 class="zh-CN">初始化SNMP工具集</h3>
	 *
	 * @param serverCount <span class="en-US">Maximum size of registered server list</span>
	 *                    <span class="zh-CN">允许注册目标主机的最大值</span>
	 * @param period      <span class="en-US">Schedule process period time (Unit: milliseconds)</span>
	 *                    <span class="zh-CN">调度处理的间隔时间（单位：毫秒）</span>
	 * @return <span class="en-US">Initialize result</span>
	 * <span class="zh-CN">初始化结果</span>
	 */
	public static boolean initialize(final int serverCount, final long period) {
		if (SNMPUtils.INSTANCE != null) {
			return Boolean.TRUE;
		}
		try {
			synchronized (SNMPUtils.class) {
				if (SNMPUtils.INSTANCE == null) {
					SNMPUtils.INSTANCE = new SNMPUtils(serverCount, period);
				}
			}
			return Boolean.TRUE;
		} catch (IOException e) {
			LOGGER.error("Init_SNMP_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Static method for retrieve singleton instance of SNMP utilities</h3>
	 * <h3 class="zh-CN">静态方法用于获取SNMP工具集单例实例对象</h3>
	 *
	 * @return <span class="en-US">Singleton instance</span>
	 * <span class="zh-CN">单例实例对象</span>
	 */
	public static SNMPUtils getInstance() {
		return SNMPUtils.INSTANCE;
	}

	/**
	 * <h3 class="en-US">Add monitor target host</h3>
	 * <h3 class="zh-CN">添加要监控的目标主机</h3>
	 *
	 * @param identifiedKey    <span class="en-US">Identify key of target host</span>
	 *                         <span class="zh-CN">目标主机的唯一标识字符串</span>
	 * @param targetHost       <span class="en-US">Target host instance</span>
	 *                         <span class="zh-CN">目标主机实例对象</span>
	 * @param pduArray         <span class="en-US">PDU instance array</span>
	 *                         <span class="zh-CN">协议数据单元实例对象数组</span>
	 * @param snmpDataOperator <span class="en-US">SNMP data operator instance</span>
	 *                         <span class="zh-CN">SNMP数据操作器实例对象</span>
	 * @return <span class="en-US">Add result</span>
	 * <span class="zh-CN">添加结果</span>
	 */
	public boolean addMonitor(final String identifiedKey, final TargetHost targetHost,
	                          final SNMPDataOperator snmpDataOperator, final PDU... pduArray) {
		if (this.existsHosts.contains(targetHost)) {
			return Boolean.TRUE;
		}

		try {
			this.existsHosts.add(targetHost);
			this.scheduledExecutorService.scheduleAtFixedRate(
					new SNMPProcessor(identifiedKey, targetHost, snmpDataOperator, pduArray),
					0L, this.period, TimeUnit.MILLISECONDS);
			return Boolean.TRUE;
		} catch (ProcessorConfigException e) {
			LOGGER.error("Add_Target_SNMP_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Destroy agent and schedule processor</h3>
	 * <h3 class="zh-CN">静态方法用于获取SNMP工具集单例实例对象</h3>
	 *
	 * @throws IOException <span class="en-US">If an error occurs when close agent</span>
	 *                     <span class="zh-CN">当关闭客户端时出现异常</span>
	 */
	public static void destroy() throws IOException {
		if (INSTANCE != null) {
			INSTANCE.scheduledExecutorService.shutdownNow();
			INSTANCE.tcpAgent.close();
			INSTANCE.tcpAgent = null;
			INSTANCE.udpAgent.close();
			INSTANCE.udpAgent = null;
			INSTANCE.existsHosts.clear();

			INSTANCE = null;
		}
	}

	/**
	 * <h3 class="en-US">Retrieve data from target host</h3>
	 * <h3 class="zh-CN">从目标主机读取数据</h3>
	 *
	 * @param protocol <span class="en-US">IP Protocol</span>
	 *                 <span class="zh-CN">IP协议</span>
	 * @param target   <span class="en-US">Target host instance</span>
	 *                 <span class="zh-CN">目标主机实例对象</span>
	 * @param pdu      <span class="en-US">PDU instance</span>
	 *                 <span class="zh-CN">协议数据单元实例对象</span>
	 * @return <span class="en-US">Read data list</span>
	 * <span class="zh-CN">读取数据列表</span>
	 */
	private List<VariableBinding> retrieveData(final IPProtocol protocol, final Target<Address> target, final PDU pdu) {
		try {
			ResponseEvent<Address> responseEvent;
			switch (protocol) {
				case TCP:
					responseEvent = this.tcpAgent.send(pdu, target);
					break;
				case UDP:
					responseEvent = this.udpAgent.send(pdu, target);
					break;
				default:
					return new ArrayList<>();
			}
			if (responseEvent != null && responseEvent.getResponse() != null) {
				PDU response = responseEvent.getResponse();
				if (response.getErrorIndex() == PDU.noError
						&& response.getErrorStatus() == PDU.noError) {
					return response.getBindingList(new OID());
				}
			}
		} catch (IOException e) {
			LOGGER.error("Retrieve_Data_SNMP_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}
		return new ArrayList<>();
	}

	/**
	 * <h2 class="en-US">SNMP processor</h2>
	 * <h2 class="zh-CN">SNMP处理器线程</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0.0 $ $Date: Oct 25, 2017 21:08:26 $
	 */
	private static final class SNMPProcessor implements Runnable {
		/**
		 * <span class="en-US">Identify key of target host</span>
		 * <span class="zh-CN">目标主机的唯一标识字符串</span>
		 */
		private final String identifiedKey;
		/**
		 * <span class="en-US">IP Protocol</span>
		 * <span class="zh-CN">IP协议</span>
		 */
		private final IPProtocol protocol;
		/**
		 * <span class="en-US">Target host instance</span>
		 * <span class="zh-CN">目标主机实例对象</span>
		 */
		private final Target<Address> target;
		/**
		 * <span class="en-US">PDU instance array</span>
		 * <span class="zh-CN">协议数据单元实例对象数组</span>
		 */
		private final PDU[] pduArray;
		/**
		 * <span class="en-US">SNMP data operator instance</span>
		 * <span class="zh-CN">SNMP数据操作器实例对象</span>
		 */
		private final SNMPDataOperator snmpDataOperator;

		/**
		 * <h3 class="en-US">Private constructor for SNMPProcessor</h3>
		 * <h3 class="zh-CN">SNMP处理器线程的私有构造方法</h3>
		 *
		 * @param identifiedKey    <span class="en-US">Identify key of target host</span>
		 *                         <span class="zh-CN">目标主机的唯一标识字符串</span>
		 * @param targetHost       <span class="en-US">Target host instance</span>
		 *                         <span class="zh-CN">目标主机实例对象</span>
		 * @param pduArray         <span class="en-US">PDU instance array</span>
		 *                         <span class="zh-CN">协议数据单元实例对象数组</span>
		 * @param snmpDataOperator <span class="en-US">SNMP data operator instance</span>
		 *                         <span class="zh-CN">SNMP数据操作器实例对象</span>
		 * @throws ProcessorConfigException the processor config exception
		 */
		public SNMPProcessor(final String identifiedKey, final TargetHost targetHost,
		                     final SNMPDataOperator snmpDataOperator, final PDU... pduArray)
				throws ProcessorConfigException {
			if (identifiedKey == null || targetHost == null || pduArray == null
					|| pduArray.length == 0 || snmpDataOperator == null) {
				throw new ProcessorConfigException(0x000000FF0001L, "Parameter_Invalid_Error");
			}
			this.identifiedKey = identifiedKey;
			this.protocol = targetHost.getProtocol();
			this.target = SNMPUtils.getInstance().generateTarget(targetHost);
			this.pduArray = pduArray;
			this.snmpDataOperator = snmpDataOperator;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see Runnable#run()
		 */
		@Override
		public void run() {
			SNMPData snmpData = new SNMPData();
			snmpData.setIdentifiedKey(this.identifiedKey);
			Arrays.asList(this.pduArray).forEach(pdu ->
					SNMPUtils.getInstance().retrieveData(this.protocol, this.target, pdu).forEach(snmpData::addData));
			this.snmpDataOperator.operateData(snmpData);
		}
	}

	/**
	 * <h3 class="en-US">Retrieve authenticate protocol OID instance</h3>
	 * <h3 class="zh-CN">SNMP处理器线程的私有构造方法</h3>
	 *
	 * @param snmpAuthProtocol <span class="en-US">SNMP Authentication Protocol</span>
	 *                         <span class="zh-CN">SNMP身份验证协议</span>
	 * @return <span class="en-US">OID instance</span>
	 * <span class="zh-CN">OID实例对象</span>
	 */
	private OID retrieveAuthProtocol(final SNMPAuthProtocol snmpAuthProtocol) {
		switch (snmpAuthProtocol) {
			case MD5:
				return AuthMD5.ID;
			case SHA:
				return AuthSHA.ID;
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Convert TargetHost instance to Target instance</h3>
	 * <h3 class="zh-CN">SNMP处理器线程的私有构造方法</h3>
	 *
	 * @param targetHost <span class="en-US">SNMP Target Host instance</span>
	 *                   <span class="zh-CN">SNMP目标主机实例对象</span>
	 * @return <span class="en-US">Converted Target instance</span>
	 * <span class="zh-CN">转换后的Target实例对象</span>
	 */
	private Target<Address> generateTarget(final TargetHost targetHost) {
		if (targetHost == null) {
			return null;
		}

		String address = null;

		switch (targetHost.getProtocol()) {
			case TCP:
				address = PROTOCOL_TCP + targetHost.getIpAddress() + "/" + targetHost.getPort();
				break;
			case UDP:
				address = PROTOCOL_UDP + targetHost.getIpAddress() + "/" + targetHost.getPort();
				break;
		}
		Target<Address> target;

		if (SNMPVersion.VERSION3.equals(targetHost.getVersion())) {
			USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
			SecurityModels.getInstance().addSecurityModel(usm);

			target = new UserTarget<>();

			OctetString securityName = null;
			OID authProtocol = null;
			OctetString authPassword = null;
			OID privProtocol = null;
			OctetString privPassword = null;

			switch (targetHost.getAuth()) {
				case NOAUTH_NOPRIV:
					target.setSecurityLevel(SecurityLevel.NOAUTH_NOPRIV);
					securityName = new OctetString("noAuthUser");
					break;
				case AUTH_NOPRIV:
					target.setSecurityLevel(SecurityLevel.AUTH_NOPRIV);
					securityName = new OctetString("authUser");
					authProtocol = retrieveAuthProtocol(targetHost.getAuthProtocol());
					authPassword = new OctetString(targetHost.getAuthPassword());
					break;
				case AUTH_PRIV:
					target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
					securityName = new OctetString("privUser");
					authProtocol = retrieveAuthProtocol(targetHost.getAuthProtocol());
					authPassword = new OctetString(targetHost.getAuthPassword());
					switch (targetHost.getPrivProtocol()) {
						case PrivDES:
							privProtocol = PrivDES.ID;
							break;
						case Priv3DES:
							privProtocol = Priv3DES.ID;
							break;
					}
					privPassword = new OctetString(targetHost.getPrivPassword());
					break;
			}

			if (securityName != null) {
				target.setSecurityName(securityName);

				UsmUser usmUser = new UsmUser(securityName, authProtocol, authPassword, privProtocol, privPassword);
				switch (targetHost.getProtocol()) {
					case TCP:
						this.tcpAgent.getUSM().addUser(usmUser);
						break;
					case UDP:
						this.udpAgent.getUSM().addUser(usmUser);
						break;
				}
			}
		} else {
			target = new CommunityTarget<>();
			((CommunityTarget<Address>) target).setCommunity(new OctetString(targetHost.getCommunity()));
		}

		target.setAddress(GenericAddress.parse(address));
		target.setRetries(targetHost.getRetries());
		target.setTimeout(targetHost.getTimeOut());

		switch (targetHost.getVersion()) {
			case VERSION1:
				target.setVersion(SnmpConstants.version1);
				break;
			case VERSION2C:
				target.setVersion(SnmpConstants.version2c);
				break;
			case VERSION3:
				target.setVersion(SnmpConstants.version3);
				break;
		}
		return target;
	}
}
