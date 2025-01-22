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
package org.nervousync.launcher;

/**
 * <h2 class="en-US">Interface class for startup launcher</h2>
 * <span class="en-US">
 * Launcher class must implement the current interface and add annotation
 * org.nervousync.annotations.launcher.Launcher at launcher class.
 * StartupManager will load launcher instance by Java SPI, and invoke startup method at system start,
 * invoke destroy method at system shutdown.
 * Users can add parameter value (type: int) at annotation org.nervousync.annotations.launcher.Launcher
 * to move the sort of launcher execute, sort type: DESC
 * </span>
 * <h2 class="zh-CN">启动器接口</h2>
 * <span class="zh-CN">
 * 启动器实现类必须实现当前接口并添加注解org.nervousync.annotations.launcher.Launcher到启动器实现类上。
 * 启动管理器会使用Java的SPI机制自动加载所有启动器实例，启动管理器会在系统启动时调用startup方法，在系统退出时调用destroy方法。
 * 用户可以通过设置一个int类型的参数值在注解org.nervousync.annotations.launcher.Launcher上，
 * 用于调整启动器的执行顺序，排序方式为：倒叙
 * </span>
 * .0
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Nov 3, 2017 16:39:41 $
 */
public interface StartupLauncher {

	/**
	 * <h3 class="en-US">Startup method</h3>
	 * <span class="en-US">StartupManager invoke this method to execute current launcher</span>
	 * <h3 class="zh-CN">启动方法</h3>
	 * <span class="zh-CN">启动管理器调用此方法来执行当前的启动器</span>
	 */
	void startup();

	/**
	 * <h3 class="en-US">Stop method</h3>
	 * <span class="en-US">StartupManager invoke this method to stop the current launcher</span>
	 * <h3 class="zh-CN">停止方法</h3>
	 * <span class="zh-CN">启动管理器调用此方法来停止当前的启动器</span>
	 */
	void stop();

	/**
	 * <h3 class="en-US">Destroy current launcher instance</h3>
	 * <h3 class="zh-CN">销毁当前启动器实例</h3>
	 */
	void destroy();

}
