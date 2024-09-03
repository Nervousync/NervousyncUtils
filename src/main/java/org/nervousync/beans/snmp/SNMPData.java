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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import org.nervousync.utils.DateTimeUtils;
import org.snmp4j.smi.VariableBinding;

/**
 * <h2 class="en-US">Reading data maps of SNMP data</h2>
 * <h2 class="zh-CN">从SNMP读取的数据结果映射</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.3 $ $Date: May 25, 2022 21:55:18 $
 */
public final class SNMPData implements Serializable {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = -9033003833049981503L;
	/**
	 * <span class="en-US">Current GMT time in milliseconds</span>
	 * <span class="zh-CN">当前GMT时间的毫秒数</span>
	 */
	private final long currentGMTTime;
	/**
	 * <span class="en-US">String value of identified key</span>
	 * <span class="zh-CN">识别代码字符串</span>
	 */
	private String identifiedKey = null;
	/**
	 * <span class="en-US">Reading data key-value map</span>
	 * <span class="zh-CN">读取数据的键值映射</span>
	 */
	private final Map<String, String> dataMap;

	/**
	 * <h3 class="en-US">Constructor for SNMPData</h3>
	 * <span class="en-US">Read current GMT time in milliseconds and initialize data map</span>
	 * <h3 class="zh-CN">SNMPData的构造函数</h3>
	 * <span class="zh-CN">读取当前的GMT时间毫秒数，并初始化数据映射表</span>
	 */
	public SNMPData() {
		this.currentGMTTime = DateTimeUtils.currentUTCTimeMillis();
		this.dataMap = new HashMap<>();
	}

	/**
	 * <h3 class="en-US">Getter method for current GMT time</h3>
	 * <h3 class="zh-CN">当前GMT时间的毫秒数的Getter方法</h3>
	 *
	 * @return <span class="en-US">Current GMT time in milliseconds</span>
	 * <span class="zh-CN">当前GMT时间的毫秒数</span>
	 */
	public long getCurrentGMTTime() {
		return currentGMTTime;
	}

	/**
	 * <h3 class="en-US">Getter method for identified key</h3>
	 * <h3 class="zh-CN">识别代码字符串的Getter方法</h3>
	 *
	 * @return <span class="en-US">String value of identified key</span>
	 * <span class="zh-CN">识别代码字符串</span>
	 */
	public String getIdentifiedKey() {
		return identifiedKey;
	}

	/**
	 * <h3 class="en-US">Setter method for identified key</h3>
	 * <h3 class="zh-CN">识别代码字符串的Setter方法</h3>
	 *
	 * @param identifiedKey <span class="en-US">String value of identified key</span>
	 *                      <span class="zh-CN">识别代码字符串</span>
	 */
	public void setIdentifiedKey(String identifiedKey) {
		this.identifiedKey = identifiedKey;
	}

	/**
	 * <h3 class="en-US">Parse instance of VariableBinding and add data to data map</h3>
	 * <h3 class="zh-CN">解析VariableBinding实例对象，并添加数据到数据映射表</h3>
	 *
	 * @param variableBinding <span class="en-US">Instance of VariableBinding</span>
	 *                        <span class="zh-CN">VariableBinding实例对象</span>
	 * @see org.snmp4j.smi.VariableBinding
	 */
	public void addData(VariableBinding variableBinding) {
		if (!this.dataMap.containsKey(variableBinding.getOid().toString())) {
			this.dataMap.put(variableBinding.getOid().toString(), variableBinding.getVariable().toString());
		}
	}

	/**
	 * <h3 class="en-US">Read data from data map by given oid string</h3>
	 * <h3 class="zh-CN">根据给定的oid字符串读取数据值</h3>
	 *
	 * @param oid <span class="en-US">oid string</span>
	 *            <span class="zh-CN">oid字符串</span>
	 * @return <span class="en-US">Mapping data</span>
	 * <span class="zh-CN">映射数据值</span>
	 */
	public String readData(final String oid) {
		return this.dataMap.get(oid);
	}

	/**
	 * <h3 class="en-US">Retrieve iterator over the elements in data map</h3>
	 * <h3 class="zh-CN">获取当前数据集元素的遍历器</h3>
	 *
	 * @return <span class="en-US">Iterator instance</span>
	 * <span class="zh-CN">遍历器实例对象</span>
	 */
	public Iterator<Entry<String, String>> iterator() {
		return this.dataMap.entrySet().iterator();
	}
}
