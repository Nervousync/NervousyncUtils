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

import org.nervousync.beans.network.NetworkInfo;
import org.nervousync.commons.Globals;
import org.nervousync.exceptions.beans.network.NetworkInfoException;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.*;

/**
 * <h2 class="en-US">System Utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Retrieve current system information.</ul>
 *     <ul>Retrieve current system Java runtime information.</ul>
 *     <ul>Generate unique identified ID for current system.</ul>
 * </span>
 * <h2 class="zh-CN">系统工具</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>获取当前系统信息</ul>
 *     <ul>获取当前系统中的Java运行环境信息</ul>
 *     <ul>生成当前系统的唯一标识ID</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Jul 24, 2015 11:43:24 $
 */
public final class SystemUtils {
    /**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
     */
    private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(SystemUtils.class);
    /**
     * <span class="en-US">Default certificate library path of Java runtime</span>
     * <span class="zh-CN">Java运行环境默认证书库地址</span>
     */
    private static final String JAVA_CERT_PATH = Globals.DEFAULT_PAGE_SEPARATOR + "lib"
            + Globals.DEFAULT_PAGE_SEPARATOR + "security" + Globals.DEFAULT_PAGE_SEPARATOR + "cacerts";
    /**
     * <span class="en-US">Current operating system name</span>
     * <span class="zh-CN">当前操作系统名称</span>
     */
    public static final String OPERATE_SYSTEM_NAME = System.getProperty("os.name");
    /**
     * <span class="en-US">Current operating system version</span>
     * <span class="zh-CN">当前操作系统版本</span>
     */
    public static final String OPERATE_SYSTEM_VERSION = System.getProperty("os.version");
    /**
     * <span class="en-US">Current JRE home folder path</span>
     * <span class="zh-CN">当前JRE主目录地址</span>
     */
    public static final String JAVA_HOME = System.getProperty("java.home");
    /**
     * <span class="en-US">Current JDK version</span>
     * <span class="zh-CN">当前JDK版本信息</span>
     */
    public static final String JDK_VERSION = System.getProperty("java.version");
    /**
     * <span class="en-US">Current JDK tmp directory path</span>
     * <span class="zh-CN">当前JDK临时目录地址</span>
     */
    public static final String JAVA_TMP_DIR = System.getProperty("java.io.tmpdir");
    /**
     * <span class="en-US">Current username</span>
     * <span class="zh-CN">当前用户名</span>
     */
    public static final String USER_NAME = System.getProperty("user.name");
    /**
     * <span class="en-US">Current user home directory path</span>
     * <span class="zh-CN">当前用户主目录地址</span>
     */
    public static final String USER_HOME = System.getProperty("user.home");
    /**
     * <span class="en-US">Current user work directory path</span>
     * <span class="zh-CN">当前用户工作目录地址</span>
     */
    public static final String USER_DIR = System.getProperty("user.dir");
    /**
     * <span class="en-US">Major version of current JDK version</span>
     * <span class="zh-CN">当前JDK的主版本号</span>
     */
    public static final int MAJOR_VERSION;
    /**
     * <span class="en-US">System identified ID</span>
     * <span class="zh-CN">系统标识ID</span>
     */
    private static final String IDENTIFIED_KEY = SystemUtils.generateIdentifiedKey();

    static {
        if (JDK_VERSION.startsWith("1.8.")) {
            MAJOR_VERSION = 8;
        } else if (JDK_VERSION.startsWith("1.7.")) {
            MAJOR_VERSION = 7;
        } else if (JDK_VERSION.startsWith("1.6.")) {
            MAJOR_VERSION = 6;
        } else if (JDK_VERSION.startsWith("1.5.")) {
            MAJOR_VERSION = 5;
        } else if (JDK_VERSION.startsWith("1.")) {
            MAJOR_VERSION = Globals.DEFAULT_VALUE_INT;
        } else {
            MAJOR_VERSION = JDK_VERSION.indexOf(".") > 0
                    ? Integer.parseInt(JDK_VERSION.substring(0, JDK_VERSION.indexOf(".")))
                    : Integer.parseInt(JDK_VERSION);
        }
    }

    /**
     * <h3 class="en-US">Private constructor for SystemUtils</h3>
     * <span class="en-US">SystemUtils is running in singleton instance mode</span>
     * <h3 class="zh-CN">SystemUtils的私有构造函数</h3>
     * <span class="zh-CN">SystemUtils使用单例模式运行</span>
     */
    private SystemUtils() {
    }

    /**
     * <h3 class="en-US">Retrieve system identified ID</h3>
     * <h3 class="zh-CN">读取系统唯一标识ID</h3>
     *
     * @return <span class="en-US">System identified ID</span>
     * <span class="zh-CN">系统标识ID</span>
     */
    public static String identifiedKey() {
        return IDENTIFIED_KEY;
    }

    /**
     * <h3 class="en-US">Check current operating system is Windows</h3>
     * <h3 class="zh-CN">判断当前操作系统为Windows</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isWindows() {
        return OPERATE_SYSTEM_NAME.toLowerCase().contains("windows");
    }

    /**
     * <h3 class="en-US">Check current operating system is Unix</h3>
     * <h3 class="zh-CN">判断当前操作系统为Unix</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isUnix() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("unix") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is Linux</h3>
     * <h3 class="zh-CN">判断当前操作系统为Linux</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isLinux() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("linux") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is Apple MacOS</h3>
     * <h3 class="zh-CN">判断当前操作系统为苹果MacOS</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isMacOS() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("mac os") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is Apple MacOS X</h3>
     * <h3 class="zh-CN">判断当前操作系统为苹果MacOS X</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isMacOSX() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("mac os x") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is OS2</h3>
     * <h3 class="zh-CN">判断当前操作系统为OS2</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isOS2() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("os/2") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is Solaris</h3>
     * <h3 class="zh-CN">判断当前操作系统为Solaris</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isSolaris() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("solaris") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is SunOS</h3>
     * <h3 class="zh-CN">判断当前操作系统为SunOS</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isSunOS() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("sunos") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is MPEiX</h3>
     * <h3 class="zh-CN">判断当前操作系统为MPEiX</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isMPEiX() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("mpe/ix") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is HP Unix</h3>
     * <h3 class="zh-CN">判断当前操作系统为HP Unix</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isHPUX() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("hp-ux") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is AIX</h3>
     * <h3 class="zh-CN">判断当前操作系统为AIX</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isAIX() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("aix") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is OS390</h3>
     * <h3 class="zh-CN">判断当前操作系统为OS390</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isOS390() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("os/390") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is FreeBSD</h3>
     * <h3 class="zh-CN">判断当前操作系统为FreeBSD</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isFreeBSD() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("freebsd") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is Irix</h3>
     * <h3 class="zh-CN">判断当前操作系统为Irix</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isIrix() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("irix") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is Digital Unix</h3>
     * <h3 class="zh-CN">判断当前操作系统为Digital Unix</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isDigitalUnix() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("digital unix") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is Netware</h3>
     * <h3 class="zh-CN">判断当前操作系统为Netware</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isNetware() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("netware") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is OSF1</h3>
     * <h3 class="zh-CN">判断当前操作系统为OSF1</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isOSF1() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("osf1") > 0;
    }

    /**
     * <h3 class="en-US">Check current operating system is OpenVMS</h3>
     * <h3 class="zh-CN">判断当前操作系统为OpenVMS</h3>
     *
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean isOpenVMS() {
        return OPERATE_SYSTEM_NAME.toLowerCase().indexOf("openvms") > 0;
    }

    /**
     * <h3 class="en-US">Retrieve default certificate library path</h3>
     * <h3 class="zh-CN">读取当前默认证书库的路径</h3>
     *
     * @return <span class="en-US">Certificate library path</span>
     * <span class="zh-CN">证书库的路径</span>
     */
    public static String systemCertPath() {
        return JAVA_HOME + JAVA_CERT_PATH;
    }

    /**
     * <h3 class="en-US">Retrieve current network interface MAC address</h3>
     * <h3 class="zh-CN">读取当前系统网卡的物理地址</h3>
     *
     * @return <span class="en-US">MAC address data bytes</span>
     * <span class="zh-CN">网卡物理地址的二进制数组</span>
     */
    public static byte[] localMac() {
        byte[] macAddress = null;
        try {
            final InetAddress localHost = InetAddress.getLocalHost();
            try {
                final NetworkInterface localInterface = NetworkInterface.getByInetAddress(localHost);
                if (localInterface != null && !localInterface.isLoopback() && localInterface.isUp()) {
                    macAddress = localInterface.getHardwareAddress();
                }
                if (macAddress == null) {
                    final Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
                    while (networkInterfaces.hasMoreElements() && macAddress == null) {
                        final NetworkInterface networkInterface = networkInterfaces.nextElement();
                        if (networkInterface != null && !networkInterface.isLoopback() && networkInterface.isUp()) {
                            macAddress = networkInterface.getHardwareAddress();
                        }
                    }
                }
            } catch (final SocketException e) {
                LOGGER.error("Retrieve_MAC_System_Error", e);
            }
            if (macAddress == null || macAddress.length == 0) {
                // Take only six bytes if the address is an IPv6 otherwise will pad with two zero bytes
                macAddress = Arrays.copyOf(localHost.getAddress(), 6);
            }
        } catch (final UnknownHostException ignored) {
            // ignored
        }
        return macAddress;
    }

    /**
     * <h3 class="en-US">Generate system identified ID</h3>
     * <h3 class="zh-CN">生成系统唯一标识ID</h3>
     *
     * @return <span class="en-US">Generated ID string</span>
     * <span class="zh-CN">生成的ID字符串</span>
     */
    private static String generateIdentifiedKey() {
        try {
            List<NetworkInfo> networkList = retrieveNetworkList();
            List<String> macAddressList = new ArrayList<>();

            for (NetworkInfo networkInfo : networkList) {
                if (!networkInfo.isVirtual() && !networkInfo.getMacAddress().isEmpty()
                        && !macAddressList.contains(networkInfo.getMacAddress())) {
                    macAddressList.add(networkInfo.getMacAddress());
                }
            }

            Collections.sort(macAddressList);
            return ConvertUtils.toHex(SecurityUtils.SHA256(macAddressList));
        } catch (Exception e) {
            LOGGER.error("Generate_Identified_ID_System_Error");
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Stack_Message_Error", e);
            }
        }

        return null;
    }

    /**
     * <h3 class="en-US">Retrieve system local network adapter list</h3>
     * <h3 class="zh-CN">获取系统物理网络适配器列表</h3>
     *
     * @return <span class="en-US">Local network adapter info list</span>
     * <span class="zh-CN">物理网络适配器列表</span>
     * @throws SocketException <span class="en-US">Retrieve network interfaces error</span>
     *                         <span class="zgs">获取网络适配器时发生错误</span>
     */
    private static List<NetworkInfo> retrieveNetworkList() throws SocketException {
        List<NetworkInfo> networkList = new ArrayList<>();
        Enumeration<NetworkInterface> enumeration = NetworkInterface.getNetworkInterfaces();
        while (enumeration.hasMoreElements()) {
            try {
                networkList.add(new NetworkInfo(enumeration.nextElement()));
            } catch (NetworkInfoException e) {
                LOGGER.error("Retrieve_Network_Interface_System_Error");
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Stack_Message_Error", e);
                }
            }
        }

        return networkList;
    }
}
