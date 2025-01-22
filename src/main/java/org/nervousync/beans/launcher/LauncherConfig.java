/*
 * Licensed to the Nervousync Studio (NSYC) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
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

package org.nervousync.beans.launcher;

import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlType;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.nervousync.beans.core.BeanObject;
import org.nervousync.beans.transfer.basic.ClassAdapter;
import org.nervousync.commons.Globals;
import org.nervousync.enumerations.launcher.StartupType;

/**
 * <h2 class="en-US">Startup Launcher configure information</h2>
 * <h2 class="zh-CN">启动器注册信息</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Feb 27, 2024 11:07:46 $
 */
@XmlType(name = "launcher_config")
@XmlRootElement(name = "launcher_config")
public final class LauncherConfig extends BeanObject {

	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 5228488917816373293L;

	/**
	 * <span class="en-US">Implement class name of startup launcher</span>
	 * <span class="zh-CN">启动器实现类名</span>
	 */
	@XmlElement(name = "launcher_class")
	@XmlJavaTypeAdapter(ClassAdapter.class)
	private Class<?> launcherClass;
	/**
	 * <span class="en-US">Startup sort code</span>
	 * <span class="zh-CN">启动排序代码</span>
	 */
	@XmlElement(name = "sort_code")
	private int sortCode = Globals.DEFAULT_VALUE_INT;
	/**
	 * <span class="en-US">Enumeration value of startup type</span>
	 * <span class="zh-CN">启动类型枚举值</span>
	 */
	@XmlElement(name = "startup_type")
	private StartupType startupType = StartupType.MANUAL;

	/**
	 * <h3 class="en-US">Constructor method for LauncherConfig</h3>
	 * <h3 class="zh-CN">启动器注册信息的构造方法</h3>
	 */
	public LauncherConfig() {
	}

	/**
	 * <h3 class="en-US">Getter method for implement class name of startup launcher</h3>
	 * <h3 class="zh-CN">启动器实现类名的Getter方法</h3>
	 *
	 * @return <span class="en-US">Implement class name of startup launcher</span>
	 * <span class="zh-CN">启动器实现类名</span>
	 */
	public Class<?> getLauncherClass() {
		return launcherClass;
	}

	/**
	 * <h3 class="en-US">Setter method for implement class name of startup launcher</h3>
	 * <h3 class="zh-CN">启动器实现类名的Setter方法</h3>
	 *
	 * @param launcherClass <span class="en-US">Implement class name of startup launcher</span>
	 *                      <span class="zh-CN">启动器实现类名</span>
	 */
	public void setLauncherClass(Class<?> launcherClass) {
		this.launcherClass = launcherClass;
	}

	/**
	 * <h3 class="en-US">Getter method for startup sort code</h3>
	 * <h3 class="zh-CN">启动排序代码的Getter方法</h3>
	 *
	 * @return <span class="en-US">Startup sort code</span>
	 * <span class="zh-CN">启动排序代码</span>
	 */
	public int getSortCode() {
		return sortCode;
	}

	/**
	 * <h3 class="en-US">Setter method for startup sort code</h3>
	 * <h3 class="zh-CN">启动排序代码的Setter方法</h3>
	 *
	 * @param sortCode <span class="en-US">Startup sort code</span>
	 *                 <span class="zh-CN">启动排序代码</span>
	 */
	public void setSortCode(int sortCode) {
		this.sortCode = sortCode;
	}

	/**
	 * <h3 class="en-US">Getter method for enumeration value of the startup type</h3>
	 * <h3 class="zh-CN">启动类型枚举值的Getter方法</h3>
	 *
	 * @return <span class="en-US">Enumeration value of startup type</span>
	 * <span class="zh-CN">启动类型枚举值</span>
	 */
	public StartupType getStartupType() {
		return startupType;
	}

	/**
	 * <h3 class="en-US">Setter method for enumeration value of the startup type</h3>
	 * <h3 class="zh-CN">启动类型枚举值的Setter方法</h3>
	 *
	 * @param startupType <span class="en-US">Enumeration value of startup type</span>
	 *                    <span class="zh-CN">启动类型枚举值</span>
	 */
	public void setStartupType(StartupType startupType) {
		this.startupType = startupType;
	}
}
