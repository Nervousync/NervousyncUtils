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
package org.nervousync.beans.ip;

import org.nervousync.enumerations.ip.IPType;
import org.nervousync.commons.Globals;

import java.io.Serializable;

/**
 * <h2 class="en-US">IP address range define</h2>
 * <h2 class="zh-CN">IP地址范围定义</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.3 $Date: Dec 10, 2021 18:25:52 $
 */
public final class IPRange implements Serializable {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 7569297312912043791L;
	/**
	 * <span class="en-US">Enumeration value of IPType</span>
	 * <span class="zh-CN">地址类型枚举值</span>
	 *
	 * @see org.nervousync.enumerations.ip.IPType
	 */
	private IPType ipType;
	/**
	 * <span class="en-US">IP range begin address</span>
	 * <span class="zh-CN">IP范围起始地址</span>
	 */
	private String beginAddress = Globals.DEFAULT_VALUE_STRING;
	/**
	 * <span class="en-US">IP range end address</span>
	 * <span class="zh-CN">IP范围终止地址</span>
	 */
	private String endAddress = Globals.DEFAULT_VALUE_STRING;

	/**
	 * <h3 class="en-US">Constructor for IPRange</h3>
	 * <h3 class="zh-CN">IPRange默认构造方法</h3>
	 */
	public IPRange() {
	}

	/**
	 * <h3 class="en-US">Getter method for IP type</h3>
	 * <h3 class="zh-CN">地址类型的Getter方法</h3>
	 *
	 * @return <span class="en-US">Value of IPType</span>
	 * <span class="zh-CN">地址类型枚举值</span>
	 * @see org.nervousync.enumerations.ip.IPType
	 */
	public IPType getIpType() {
		return ipType;
	}

	/**
	 * <h3 class="en-US">Setter method for IP type</h3>
	 * <h3 class="zh-CN">地址类型的Setter方法</h3>
	 *
	 * @param ipType <span class="en-US">Value of IPType</span>
	 *               <span class="zh-CN">地址类型枚举值</span>
	 * @see org.nervousync.enumerations.ip.IPType
	 */
	public void setIpType(IPType ipType) {
		this.ipType = ipType;
	}

	/**
	 * <h3 class="en-US">Getter method for IP range begin address</h3>
	 * <h3 class="zh-CN">IP范围起始地址的Getter方法</h3>
	 *
	 * @return <span class="en-US">Value of IP range begin address</span>
	 * <span class="zh-CN">IP范围起始地址</span>
	 */
	public String getBeginAddress() {
		return beginAddress;
	}

	/**
	 * <h3 class="en-US">Setter method for IP range begin address</h3>
	 * <h3 class="zh-CN">IP范围起始地址的Setter方法</h3>
	 *
	 * @param beginAddress <span class="en-US">Value of IP range begin address</span>
	 *                     <span class="zh-CN">IP范围起始地址</span>
	 */
	public void setBeginAddress(String beginAddress) {
		this.beginAddress = beginAddress;
	}

	/**
	 * <h3 class="en-US">Getter method for IP range end address</h3>
	 * <h3 class="zh-CN">IP范围终止地址的Getter方法</h3>
	 *
	 * @return <span class="en-US">Value of IP range end address</span>
	 * <span class="zh-CN">IP范围终止地址</span>
	 */
	public String getEndAddress() {
		return endAddress;
	}

	/**
	 * <h3 class="en-US">Setter method for IP range end address</h3>
	 * <h3 class="zh-CN">IP范围终止地址的Setter方法</h3>
	 *
	 * @param endAddress <span class="en-US">Value of IP range end address</span>
	 *                   <span class="zh-CN">IP范围终止地址</span>
	 */
	public void setEndAddress(String endAddress) {
		this.endAddress = endAddress;
	}
}
