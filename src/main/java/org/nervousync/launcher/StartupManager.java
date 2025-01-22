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

import jakarta.annotation.Nonnull;
import org.nervousync.annotations.launcher.Launcher;
import org.nervousync.annotations.provider.Provider;
import org.nervousync.beans.launcher.LauncherConfig;
import org.nervousync.beans.launcher.StartupConfig;
import org.nervousync.commons.Globals;
import org.nervousync.configs.ConfigureManager;
import org.nervousync.enumerations.launcher.StartupType;
import org.nervousync.utils.DateTimeUtils;
import org.nervousync.utils.ObjectUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * <h2 class="en-US">Startup Manager</h2>
 * <span class="en-US">Running in singleton mode</span>
 * <h2 class="zh-CN">启动管理器</h2>
 * <span class="en-US">使用单例模式运行</span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jun 28, 2022 15:25:33 $
 */
public final class StartupManager {
	private static final long SCHEDULE_PERIOD = 30 * 1000L;
	/**
	 * <span class="en-US">Singleton instance of StartupManager</span>
	 * <span class="en-US">StartupManager的单例对象实例</span>
	 */
	private static StartupManager INSTANCE = null;
	/**
	 * <span class="en-US">Startup manager configure instance</span>
	 * <span class="en-US">启动器配置信息实例对象</span>
	 */
	private final StartupConfig startupConfig;
	/**
	 * <span class="en-US">Registered startup launcher instance</span>
	 * <span class="en-US">已注册的启动器实例</span>
	 */
	private final List<StartupLauncher> runningLaunchers;
	/**
	 * <span class="en-US">Schedule executor for update startup launcher configure</span>
	 * <span class="en-US">启动器配置信息更新调度程序</span>
	 */
	private final ScheduledExecutorService scheduledExecutorService;
	/**
	 * <span class="en-US">Schedule task running status</span>
	 * <span class="en-US">调度任务执行状态</span>
	 */
	private boolean running = Boolean.FALSE;

	/**
	 * <h3 class="en-US">Private constructor method for StartupManager</h3>
	 * <span class="en-US">StartupManager will automatically add a hook to schedule execute destroy method when system will shutdown.</span>
	 * <h3 class="zh-CN">启动管理器的私有构造方法</h3>
	 * <span class="zh-CN">启动管理器会自动添加一个钩子程序用于在系统退出时调用destroy方法。</span>
	 */
	private StartupManager(final StartupConfig startupConfig) {
		this.startupConfig = (startupConfig == null) ? new StartupConfig() : startupConfig;
		this.runningLaunchers = new ArrayList<>();
		this.scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
		this.scheduledExecutorService.scheduleWithFixedDelay(this::scanConfig, Globals.DEFAULT_SCHEDULE_DELAY,
				SCHEDULE_PERIOD, TimeUnit.MILLISECONDS);
		Runtime.getRuntime().addShutdownHook(new Thread(() -> {
			if (StartupManager.INSTANCE != null) {
				StartupManager.INSTANCE.destroy();
				StartupManager.INSTANCE = null;
			}
		}));
		this.startupConfig.getRegisteredLaunchers()
				.stream()
				.filter(launcherConfig -> StartupType.AUTO.equals(launcherConfig.getStartupType()))
				.forEach(this::startLauncher);
	}

	/**
	 * <h3 class="en-US">Static method for initialize StartupManager and execute startup method from all launchers</h3>
	 * <h3 class="zh-CN">静态方法用于初始化启动管理器并执行所有启动器的startup方法</h3>
	 */
	public static void initialize() {
		if (StartupManager.INSTANCE == null) {
			StartupManager.INSTANCE =
					Optional.ofNullable(ConfigureManager.getInstance())
							.map(configureManager ->
									new StartupManager(configureManager.readConfigure(StartupConfig.class)))
							.orElse(null);
		}
	}

	/**
	 * <h3 class="en-US">Obtain instance of startup manager</h3>
	 * <h3 class="zh-CN">获取启动管理器实例对象</h3>
	 *
	 * @return <span class="en-US">Startup manager instance</span>
	 * <span class="en-US">启动管理器实例对象</span>
	 */
	public static StartupManager getInstance() {
		if (StartupManager.INSTANCE == null) {
			initialize();
		}
		return StartupManager.INSTANCE;
	}

	/**
	 * <h3 class="en-US">Obtain the registered launcher configure information list</h3>
	 * <h3 class="zh-CN">获取已注册的启动器配置信息列表</h3>
	 *
	 * @return <span class="en-US">Launcher configure information list</span>
	 * <span class="en-US">启动器配置信息列表</span>
	 */
	public List<LauncherConfig> registeredLaunchers() {
		return this.startupConfig.getRegisteredLaunchers();
	}

	public void config(final String className, final StartupType startupType) {
		final AtomicBoolean modified = new AtomicBoolean(Boolean.FALSE);
		long startTime = DateTimeUtils.currentUTCTimeMillis();

		while (true) {
			if (!this.running) {
				this.running = Boolean.TRUE;
				break;
			}
			if (1000L < (DateTimeUtils.currentUTCTimeMillis() - startTime)) {
				return;
			}
		}
		List<LauncherConfig> registeredLaunchers = this.startupConfig.getRegisteredLaunchers();
		registeredLaunchers.replaceAll(launcherConfig -> {
			if (ObjectUtils.nullSafeEquals(className, launcherConfig.getLauncherClass().getName())
					&& !ObjectUtils.nullSafeEquals(launcherConfig.getStartupType(), startupType)) {
				launcherConfig.setStartupType(startupType);
				modified.set(Boolean.TRUE);
			}
			return launcherConfig;
		});

		if (modified.get()) {
			this.startupConfig.setRegisteredLaunchers(registeredLaunchers);
			this.saveConfig();
		}

		this.running = Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Start registered launcher</h3>
	 * <h3 class="zh-CN">启动注册的启动器</h3>
	 *
	 * @param className <span class="en-US">Launcher class name</span>
	 *                  <span class="en-US">启动器类名</span>
	 */
	public void startup(final String className) {
		if (this.runningLauncher(className)) {
			return;
		}
		this.startupConfig.getRegisteredLaunchers()
				.stream()
				.filter(launcherConfig ->
						ObjectUtils.nullSafeEquals(className, launcherConfig.getLauncherClass().getName()))
				.filter(launcherConfig -> !StartupType.DISABLE.equals(launcherConfig.getStartupType()))
				.forEach(this::startLauncher);
	}

	/**
	 * <h3 class="en-US">Stop registered launcher</h3>
	 * <h3 class="zh-CN">停止注册的启动器</h3>
	 *
	 * @param className <span class="en-US">Launcher class name</span>
	 *                  <span class="en-US">启动器类名</span>
	 */
	public void stop(final String className) {
		if (this.runningLauncher(className)) {
			this.startupConfig.getRegisteredLaunchers()
					.stream()
					.filter(launcherConfig ->
							ObjectUtils.nullSafeEquals(className, launcherConfig.getLauncherClass().getName()))
					.filter(launcherConfig -> !StartupType.DISABLE.equals(launcherConfig.getStartupType()))
					.forEach(launcherConfig ->
							this.runningLaunchers.removeIf(startupLauncher -> {
								if (ObjectUtils.nullSafeEquals(launcherConfig.getLauncherClass(),
										startupLauncher.getClass())) {
									startupLauncher.stop();
									return Boolean.TRUE;
								}
								return Boolean.FALSE;
							}));
		}
	}

	/**
	 * <h3 class="en-US">Restart registered launcher</h3>
	 * <h3 class="zh-CN">重启注册的启动器</h3>
	 *
	 * @param className <span class="en-US">Launcher class name</span>
	 *                  <span class="en-US">启动器类名</span>
	 */
	public void restart(final String className) {
		this.startupConfig.getRegisteredLaunchers()
				.stream()
				.filter(launcherConfig ->
						ObjectUtils.nullSafeEquals(className, launcherConfig.getLauncherClass().getName()))
				.filter(launcherConfig -> !StartupType.DISABLE.equals(launcherConfig.getStartupType()))
				.forEach(launcherConfig -> {
					if (this.runningLauncher(className)) {
						this.runningLaunchers.stream()
								.filter(startupLauncher ->
										ObjectUtils.nullSafeEquals(launcherConfig.getLauncherClass(),
												startupLauncher.getClass()))
								.forEach(startupLauncher -> {
									startupLauncher.stop();
									startupLauncher.startup();
								});
					} else {
						this.startLauncher(launcherConfig);
					}
				});
	}

	private boolean runningLauncher(@Nonnull final String className) {
		return this.runningLaunchers.stream()
				.anyMatch(startupLauncher -> ObjectUtils.nullSafeEquals(className, startupLauncher.getClass().getName()));
	}

	/**
	 * <h3 class="en-US">Start registered launcher</h3>
	 * <h3 class="zh-CN">启动注册的启动器</h3>
	 *
	 * @param launcherConfig <span class="en-US">Launcher configure information instance</span>
	 *                       <span class="en-US">启动器配置信息实例对象</span>
	 */
	private void startLauncher(@Nonnull final LauncherConfig launcherConfig) {
		if (this.runningLaunchers.stream().noneMatch(startupLauncher ->
				ObjectUtils.nullSafeEquals(launcherConfig.getLauncherClass(), startupLauncher.getClass()))) {
			StartupLauncher startupLauncher =
					(StartupLauncher) ObjectUtils.newInstance(launcherConfig.getLauncherClass());
			startupLauncher.startup();
			this.runningLaunchers.add(startupLauncher);
		}
	}

	/**
	 * <h3 class="en-US">Schedule task, using for checking launcher configure modified</h3>
	 * <h3 class="zh-CN">调度任务，用于扫描系统中启动器的修改</h3>
	 */
	private void scanConfig() {
		if (this.running) {
			return;
		}

		this.running = Boolean.TRUE;

		List<Class<?>> scannedClasses = new ArrayList<>();
		AtomicBoolean modified = new AtomicBoolean(Boolean.FALSE);
		List<LauncherConfig> registeredLaunchers = this.startupConfig.getRegisteredLaunchers();
		ServiceLoader.load(StartupLauncher.class).forEach(startupLauncher -> {
			Class<?> launcherClass = startupLauncher.getClass();
			if (launcherClass.isAnnotationPresent(Provider.class) && launcherClass.isAnnotationPresent(Launcher.class)) {
				scannedClasses.add(launcherClass);
				Launcher launcher = launcherClass.getAnnotation(Launcher.class);
				if (registeredLaunchers.stream().anyMatch(launcherConfig ->
						ObjectUtils.nullSafeEquals(launcherClass, launcherConfig.getLauncherClass()))) {
					registeredLaunchers.replaceAll(launcherConfig -> {
						if (ObjectUtils.nullSafeEquals(launcherClass, launcherConfig.getLauncherClass())
								&& !ObjectUtils.nullSafeEquals(launcher.value(), launcherConfig.getStartupType())) {
							launcherConfig.setStartupType(launcher.value());
							modified.set(Boolean.TRUE);
						}
						return launcherConfig;
					});
				} else {
					LauncherConfig launcherConfig = new LauncherConfig();

					launcherConfig.setLauncherClass(launcherClass);
					launcherConfig.setStartupType(launcher.value());

					registeredLaunchers.add(launcherConfig);

					modified.set(Boolean.TRUE);
				}
			}
		});

		if (registeredLaunchers.removeIf(launcherConfig ->
				!scannedClasses.contains(launcherConfig.getLauncherClass()))) {
			modified.set(Boolean.TRUE);
		}
		if (modified.get()) {
			this.startupConfig.setRegisteredLaunchers(registeredLaunchers);
			this.saveConfig();
		}

		this.running = Boolean.FALSE;
	}

	private void saveConfig() {
		this.startupConfig.setLastModify(DateTimeUtils.currentUTCTimeMillis());
		Optional.ofNullable(ConfigureManager.getInstance())
				.ifPresent(configureManager -> configureManager.saveConfigure(this.startupConfig));
	}

	/**
	 * <h3 class="en-US">Destroy all registered launcher instance</h3>
	 * <h3 class="zh-CN">销毁所有已注册的启动器实例</h3>
	 */
	private void destroy() {
		this.runningLaunchers.forEach(StartupLauncher::destroy);
		this.runningLaunchers.clear();
		this.scheduledExecutorService.shutdown();
	}
}
