# Java开发工具包

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.nervousync/utils-jdk11/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.nervousync/utils-jdk11/)
[![License](https://img.shields.io/github/license/wmkm0113/utils-jdk11.svg)](https://github.com/wmkm0113/utils-jdk11/blob/mainline/LICENSE)
![Language](https://img.shields.io/badge/language-Java-green)
[![Twitter:wmkm0113](https://img.shields.io/twitter/follow/wmkm0113?label=Follow)](https://twitter.com/wmkm0113)

[English](README.md)
简体中文
[繁體中文](README_zh_TW.md)

Java开发工具包是为了提供接口稳定、集成简单、可重用的工具包，同时优化了第三方类库的引用。工具包中包含了很多经常用到的工具类和功能模块，涵盖了广泛的应用场景， 
工具包提供了一套简洁而强大的API，帮助开发人员更高效地编写Java代码，无论是处理日期和时间、字符串操作、文件操作或网络请求的发送与处理，还是发送电子邮件、使用SNMP进行性能监控、统一的配置文件管理，
又或者是一次性密码支持、X.509证书的操作、任务管理器等，该工具包都提供了丰富的模块、功能和方法。

## 目录
* [JDK版本](#JDK版本)
* [生命周期](#生命周期)
* [使用方法](#使用方法)
* [基础工具](#基础工具)
  + [JavaBean工具类](#javabean工具类)
  + [X.509证书工具类](#x509证书工具类)
  + [集合操作工具类](#集合操作工具类)
  + [数据转换工具类](#数据转换工具类)
  + [Cookie工具类](#cookie工具类)
  + [随机ID生成工具类](#随机ID生成工具类)
  + [图片工具类](#图片工具类)
  + [IP地址工具类](#ip地址工具类)
  + [地理坐标工具类](#地理坐标工具类)
  + [电子邮件工具类](#电子邮件工具类)
  + [一次性密码工具类](#一次性密码工具类)
  + [属性信息工具类](#属性信息工具类)
  + [二进制数据操作工具类](#二进制数据操作工具类)
  + [网络请求工具类](#网络请求工具类)
  + [数据安全工具类](#数据安全工具类)
  + [WebService工具类](#WebService工具类)
  + [字符串操作工具类](#字符串操作工具类)
  + [数据结构](#数据结构)
* [JavaBean与 XML/JSON/YAML 字符串的互相转换](#javabean与-xmljsonyaml-字符串的互相转换)
* [安全工厂](#安全工厂)
* [配置文件管理器](#配置文件管理器)
* [程序启动管理器](#程序启动管理器)
* [国际化支持](#国际化支持)
  + [创建国际化资源文件（必须）](#1-创建国际化资源文件必须)
  + [在需要的地方添加国际化支持（必须）](#2-在需要的地方添加国际化支持必须)
  + [向自定义异常添加国际化支持（可选）](#3-向自定义异常添加国际化支持可选操作)
  + [向日志中添加国际化支持（可选）](#4-向日志中添加国际化支持可选操作)
  + [打包时合并资源文件（可选）](#5-打包时合并资源文件可选操作)
* [文件操作的扩展](#文件操作的扩展)
  + [Zip文件操作](#zip文件操作)
  + [随机操作文件](#随机操作文件)
* [贡献与反馈](#贡献与反馈)
* [赞助与鸣谢](#赞助与鸣谢)

## JDK版本：
**编译：** OpenJDK 11   
**运行：** OpenJDK 11+ 或兼容版本

## 生命周期:
**功能冻结：** 2026年12月31日   
**安全更新：** 2029年12月31日

## 使用方法
**Maven：**
```
<dependency>
    <groupId>org.nervousync</groupId>
	<artifactId>utils-jdk11</artifactId>
    <version>${version}</version>
</dependency>
```
**Gradle：**
```
Manual: compileOnly group: 'org.nervousync', name: 'utils-jdk11', version: '${version}'
Short: compileOnly 'org.nervousync:utils-jdk11:${version}'
```
**SBT：**
```
libraryDependencies += "org.nervousync" % "utils-jdk11" % "${version}" % "provided"
```
**Ivy：**
```
<dependency org="org.nervousync" name="utils-jdk11" rev="${version}"/>
```

## 基础工具
### JavaBean工具类
**类名** org.nervousync.utils.BeanUtils  
* 根据属性名称从源数据对象复制数据到目标数据对象
* 根据BeanProperty注解从源数据对象数组复制数据到目标数据对象
* 根据BeanProperty注解从源数据对象复制数据到目标数据对象数组

### X.509证书工具类
**类名** org.nervousync.utils.CertificateUtils  
* 生成密钥对
* 签发X.509证书
* 从证书文件、PKCS12文件或二进制数据中读取X.509证书
* 验证 X.509 证书的有效期、数字签名
* 从PKCS12文件或二进制数据中读取公钥和私钥
* 生成PKCS12文件

### 集合操作工具类
**类名** org.nervousync.utils.CollectionUtils
* 检查集合是否为空
* 检查集合是否包含目标对象
* 检查两个集合是否包含同一元素
* 检查集合是否有唯一元素
* 转换对象为列表
* 合并数组到列表中
* 合并属性信息实例到哈希表中
* 从集合中寻找第一个符合要求的元素

### 数据转换工具类
**类名** org.nervousync.utils.ConvertUtils
* 转换字节数组为十六进制字符串
* 转换字节数组为字符串
* 转换字节数组为实例对象
* 转换任意实例对象为字节数组
* 转换属性信息为数据映射表

### Cookie工具类
**类名** org.nervousync.utils.CookieUtils  
需要添加依赖：
```
<dependency>
    <groupId>jakarta.servlet</groupId>
	<artifactId>jakarta.servlet-api</artifactId>
    <version>5.0.0 or higher</version>
</dependency>
```
* 设置Cookie值
* 读取Cookie值
* 删除Cookie值

### 随机ID生成工具类
**类名** org.nervousync.utils.IDUtils  
* ID生成工具，使用Java SPI注册生成器实现类。
* 已集成的生成器：UUID 版本1到版本5, 雪花算法和NanoID.  
**自定义生成器：**   
生成器实现类必须实现接口org.nervousync.generator.IGenerator，
并在META-INF/services文件夹下创建文件名为org.nervousync.generator.IGenerator的文件，文件中写明实现类的完整名称（包名+类名）

### 图片工具类
**类名** org.nervousync.utils.ImageUtils  
* 读取图片的宽度、高度、宽高比
* 图片操作：剪切、缩放、添加水印、计算汉明距离（dHash/pHash）、计算数字签名（dHash/pHash）

### IP地址工具类
**类名** org.nervousync.utils.IPUtils  
* 根据给定的地址和CIDR，计算IP地址范围
* 在子网掩码和CIDR之间转换数据
* 在IPv4和IPv6之间转换数据
* 在IP地址和BigInteger之间转换数据
* 将压缩显示的IPv6地址展开

### 地理坐标工具类
**类名** org.nervousync.utils.LocationUtils  
* 在不同坐标系间转换数据，支持的坐标系：WGS84(GPS)/GCJ02/BD09
* 计算两个物理坐标之间的距离，单位：公里

### 电子邮件工具类
**类名** org.nervousync.utils.MailUtils  
* 发送接收电子邮件（支持协议：IMAP/POP3/SMTP）
* 获取文件夹中的电子邮件数量
* 列出所有文件夹名称
* 自动下载电子邮件中包含的附件
* 验证电子邮件签名
* 添加电子签名到邮件

### 一次性密码工具类
**类名** org.nervousync.utils.OTPUtils  
* 计算一次性密码算法的修正时间值
* 生成随机密钥
* 生成基于HMAC算法加密的一次性密码/基于时间戳算法的一次性密码值
* 验证基于HMAC算法加密的一次性密码/基于时间戳算法的一次性密码值

### 属性信息工具类
**类名** org.nervousync.utils.PropertiesUtils  
* 从字符串/本地文件/网络文件/输入流中读取属性文件
* 修改属性文件
* 将属性文件保存到目标地址

### 二进制数据操作工具类
**类名** org.nervousync.utils.RawUtils  
* 从二进制数组中读取boolean/short/int/long/String类型的数据
* 向二进制数组中写入boolean/short/int/long/String类型的数据
* 转换字节数组为二进制数组
* 转换位数组为字节

### 网络请求工具类
**类名** org.nervousync.utils.RequestUtils
* 解析HTTP方法字符串为HttpMethodOption
* 解析域名信息为IP地址
* 读取和验证服务器的SSL证书
* 发送请求并解析响应数据为字符串或指定的JavaBean
* 自由转换查询字符串和参数映射表
* 检查用户的角色信息，使用<code>request.isUserInRole</code>实现
* 支持使用代理服务器访问目标地址
* 支持自定义SSL证书进行验证

### 数据安全工具类
**类名** org.nervousync.utils.SecurityUtils  
* CRC多项式:  CRC-16/ISO-IEC-14443-3-A,CRC-32/JAMCRC,CRC-4/INTERLAKEN,CRC-16/TELEDISK,CRC-32/MPEG-2,CRC-16/GSM,CRC-6/GSM,CRC-7/UMTS,CRC-32/BZIP2,CRC-8/I-CODE,CRC-16/IBM-SDLC,CRC-16/LJ1200,CRC-10/ATM,CRC-8/NRSC-5,CRC-5/USB,CRC-7/ROHC,CRC-12/UMTS,CRC-8/BLUETOOTH,CRC-14/GSM,CRC-8/SMBUS,CRC-8/TECH-3250,CRC-5/G-704,CRC-16/MODBUS,CRC-12/DECT,CRC-7/MMC,CRC-16/CMS,CRC-24/FLEXRAY-A,CRC-24/FLEXRAY-B,CRC-32/ISO-HDLC,CRC-21/CAN-FD,CRC-8/LTE,CRC-15/CAN,CRC-24/LTE-A,CRC-30/CDMA,CRC-3/GSM,CRC-24/LTE-B,CRC-24/OPENPGP,CRC-12/CDMA2000,CRC-16/MAXIM-DOW,CRC-16/XMODEM,CRC-6/G-704,CRC-24/OS-9,CRC-16/DNP,CRC-32/AIXM,CRC-10/CDMA2000,CRC-6/CDMA2000-A,CRC-6/CDMA2000-B,CRC-16/TMS37157,CRC-16/UMTS,CRC-32/XFER,CRC-8/ROHC,CRC-16/DECT-R,CRC-8/WCDMA,CRC-8/DVB-S2,CRC-15/MPT1327,CRC-16/DECT-X,CRC-6/DARC,CRC-16/DDS-110,CRC-32/ISCSI,CRC-16/USB,CRC-8/MIFARE-MAD,CRC-8/AUTOSAR,CRC-16/KERMIT,CRC-16/IBM-3740,CRC-4/G-704,CRC-16/RIELLO,CRC-16/EN-13757,CRC-16/NRSC-5,CRC-14/DARC,CRC-31/PHILIPS,CRC-5/EPC-C1G2,CRC-32/BASE91-D,CRC-16/ARC,CRC-16/MCRF4XX,CRC-16/T10-DIF,CRC-24/INTERLAKEN,CRC-3/ROHC,CRC-13/BBC,CRC-11/UMTS,CRC-16/SPI-FUJITSU,CRC-10/GSM,CRC-8/DARC,CRC-8/OPENSAFETY,CRC-12/GSM,CRC-32/CKSUM,CRC-16/PROFIBUS,CRC-8/GSM-B,CRC-8/GSM-A,CRC-8/SAE-J1850,CRC-8/CDMA2000,CRC-8/MAXIM-DOW,CRC-16/GENIBUS,CRC-8/I-432-1,CRC-17/CAN-FD,CRC-16/OPENSAFETY-B,CRC-32/CD-ROM-EDC,CRC-16/OPENSAFETY-A,CRC-32/AUTOSAR,CRC-16/CDMA2000,CRC-11/FLEXRAY,CRC-24/BLE  
* 摘要算法: MD5/HmacMD5/SHA1/HmacSHA1/SHA2/HmacSHA2/SHA3/HmacSHA3/SHAKE128/SHAKE256/SM3/HmacSM3  
* 对称加密算法: Blowfish/DES/TripleDES/SM4/AES/RC2/RC4/RC5/RC6  
* 非对称加密算法: RSA/SM2

### WebService工具类
**类名** org.nervousync.utils.ServiceUtils  
* 生成SOAP请求客户端
* 生成Restful请求客户端并处理请求

### 字符串操作工具类
**类名** org.nervousync.utils.StringUtils  
* 使用Base32/Base64编码给定的二进制字节数组
* 将给定的Base32/Base64编码字符串解码为二进制字节数组
* 将给定的字符串编码为霍夫曼树结果实例对象
* 去除字符串中的空格
* 检查给定的字符串是否为MD5值/UUID/电话号码/电子邮件地址等
* 检查给定的字符串是否为空/非空/包含字符串等
* 使用给定的分隔符分割字符串
* 根据规则截取字符串
* 验证给定的字符串是否符合代码类型

### 数据结构
* 霍夫曼树
* 多叉树

## JavaBean与 XML/JSON/YAML 字符串的互相转换
任何继承 org.nervousync.bean.core.BeanObject 的 JavaBean 类都可以轻松地在对象实例和 XML/JSON/YAML 字符串之间进行转换。
JavaBean 与 XML 的转换是通过JAXB实现，与 JSON/YAML 的转换是通过Jackson实现。   
**1、添加父类**   
开发人员修改需要转换为 XML/JSON/YAML 字符串的JavaBean，使JavaBean继承 org.nervousync.bean.core.BeanObject 抽象类。   
**2、添加注解**   
在JavaBean的属性上添加对应的注解，如果需要转换为XML，请添加JAXB需要的注解（如：XmlRootElement/XmlElement），或Jackson注解（如JsonProperty）等。   
**3、转换为 XML/JSON/YAML**   
调用 toXML 方法，将JavaBean实例对象转换为XML字符串。   

| 参数名             | 数据类型 | 用途                                                     |
|-----------------|------|--------------------------------------------------------|
| outputFragment  | 布尔值  | 是否输出XML声明字符串（`<?xml version="1.0" encoding="UTF-8"?>`） |
| formattedOutput | 布尔值  | 是否格式化输出的XML字符串                                         |
| encoding        | 字符串  | 输出字符串的编码集（默认为UTF-8）                                    |
调用 toJson 方法，将JavaBean实例对象转换为JSON字符串。或调用 toFormattedJson 方法，将JavaBean实例对象转换为格式化后的JSON字符串。   
调用 toYaml 方法，将JavaBean实例对象转换为XML字符串。或调用 toFormattedYaml 方法，将JavaBean实例对象转换为格式化后的YAML字符串。   
**4、转换为JavaBean**   
通过调用 org.nervousync.utils.StringUtils 的 stringToObject 静态方法，可以将字符串转换为JavaBean实例对象。

| 参数名         | 数据类型  | 用途                   |
|-------------|-------|----------------------|
| string      | 字符串   | 需要转换为JavaBean的字符串    |
| encoding    | 字符串   | 字符串的编码集（默认为UTF-8）    |
| beanClass   | Class | JavaBean的类定义         |
| schemaPaths | 字符串数组 | 用于验证XML字符串的XSD文件路径数组 |

通过调用 org.nervousync.utils.StringUtils 的 fileToObject 静态方法，可以将磁盘文件转换为JavaBean实例对象，文件中的数据类型根据文件扩展名确定。

| 参数名         | 数据类型  | 用途                   |
|-------------|-------|----------------------|
| filePath    | 字符串   | 需要转换为JavaBean的文件存储路径 |
| beanClass   | Class | JavaBean的类定义         |
| schemaPaths | 字符串数组 | 用于验证XML字符串的XSD文件路径数组 |   
**5、XSD文档**   
为了验证XML文件的合法性，最常用的方法是使用XSD文档来对XML文件进行验证，程序开发人员可以将XSD文档存储到程序包中，并通过简单的配置，让系统可以找到程序包中的XSD文档。
+ 添加XSD文档到程序包中，并记录存储路径
+ 在META-INF文件夹中创建nervousync.schemas文件，文件格式为：namespace_uri=对应XSD文档存储路径，如果存在多个XSD文档定义，则每个XSD映射单独一行
+ 转换为JavaBean的方法中，参数 “schemaPaths” 可以为 namespace_uri

## 安全工厂
**类名** org.nervousync.security.factory.SecureFactory   
工具包提供了一个安全工厂类来帮助开发人员保存不同的加密解密配置信息，方便开发人员对数据进行便捷的加密解密操作。   
**安全工厂初始化**   
安全工厂会自动读取配置文件，并将安全配置信息注册到安全工厂。   
**安全配置的添加**   
调用 SecureFactory 的 registerConfig 静态方法添加新的安全配置信息。

| 参数名             | 数据类型               | 用途            |
|-----------------|--------------------|---------------|
| secureName      | 字符串                | 安全配置唯一识别代码    |
| secureAlgorithm | SecureAlgorithm枚举值 | 指定加密解密使用的算法类型 |
**数据加密**   
调用 SecureFactory 的 encrypt 静态方法完成数据的加密操作，返回加密后的数据。

| 参数名         | 数据类型 | 用途                                 |
|-------------|------|------------------------------------|
| secureName  | 字符串  | 安全配置唯一识别代码（如果为空或未找到，则使用系统安全唯一识别代码） |
| dataContent | 字符串  | 需要加密的数据                            |
**数据解密**   
调用 SecureFactory 的 decrypt 静态方法完成数据的加密操作，返回加密后的数据。

| 参数名         | 数据类型 | 用途                                 |
|-------------|------|------------------------------------|
| secureName  | 字符串  | 安全配置唯一识别代码（如果为空或未找到，则使用系统安全唯一识别代码） |
| dataContent | 字符串  | 需要解密的数据                            |

## 配置文件管理器
**类名** org.nervousync.configs.ConfigureManager  
在系统开发的过程中，经常会遇到各种不同的配置文件，为了统一对项目中的配置文件进行管理，在开发包中提供了一个配置文件的统一管理器。
开发人员可以通过调用 ConfigureManager 的 getInstance 静态方法获取配置文件管理器的实例对象，来进行配置文件的相关操作。   
**管理器的初始化**   
通过调用 ConfigureManager 的 initialize 静态方法进行配置文件管理器的初始化，开发人员可以通过传入参数 "customPath" 来设置配置文件的存储位置。
如果参数 "customPath" 为 null 或空字符串，配置文件管理器会在当前用户的工作目录下创建名为".configs"的文件夹，并将此文件夹作为默认的配置文件存储路径。   
**配置文件的读取**   
通过调用 ConfigureManager 的 readConfigure 方法读取配置文件信息，传入的参数为配置文件的JavaBean定义类。如果存在同一类型的多个配置文件，可以传入一个类型为字符串的 suffix 参数，用于标识不同的配置文件。   
**配置文件的保存**   
通过调用 ConfigureManager 的 saveConfigure 方法保存配置文件信息，传入的参数为配置文件的JavaBean实例对象。如果存在同一类型的多个配置文件，可以传入一个类型为字符串的 suffix 参数，用于标识不同的配置文件。   
**配置文件的移除**
通过调用 ConfigureManager 的 removeConfigure 方法移除配置文件信息，传入的参数为配置文件的JavaBean定义类，同时需要传入一个类型为字符串的 suffix 参数，用于移除特定的配置文件。
**注意：** 如果传入的参数 suffix 为 null 或空字符串，则移除指定类型的所有配置文件。
**配置文件的自动加载**
让需要自动加载配置文件的类继承 org.nervousync.configs.AutoConfig 抽象类，在类中添加类型为配置文件类的属性，并在属性上添加 org.nervousync.annotations.configs.Configure 注解，
如果此类型的配置文件存在多个，则可以通过 org.nervousync.annotations.configs.Configure 注解的 value 属性指定使用哪一个配置文件。   
**配置文件的密码保护**   
在配置文件中总会涉及到各种密码的保存，为了防止密码通过配置文件泄露，开发人员可以在配置文件JavaBean定义类的密码属性上，添加 org.nervousync.annotations.configs.Password 注解，
通过 org.nervousync.annotations.configs.Password 注解的 value 属性来指定需要使用的加密方式（通过安全工厂实现），系统会完成明文密码在存储到磁盘时自动加密，还可以在从磁盘读取时自动解密。

## 程序启动管理器
**类名** org.nervousync.launcher.StartupManager   
工具包提供了一个可以自动或手动执行的程序启动管理器，启动器使用Java的SPI模式加载所有 org.nervousync.launcher.StartupLauncher 接口的实现类，
并根据实现类上添加的 org.nervousync.annotations.launcher.Launcher 注解的 value 属性值，进行启动器的执行。   
org.nervousync.annotations.launcher.Launcher 注解的 value 属性值为启动类型的枚举值，允许的值为 AUTO（自动）/MANUAL（手动）/DISABLE（禁用）。
程序开发人员需要使用程序启动管理器时，需要显式调用 org.nervousync.launcher.StartupManager 的 initialize 静态方法，工具包会自动扫描并加载所有启动器，并在完成加载后，自动启动类型为 AUTO（自动）的启动器。
程序启动管理器在初始化时会在系统中注册钩子程序，当主程序正常退出时，会自动执行程序启动管理器的 destroy 方法，关闭所有正在运行的启动器。   
**启动器的开发**   
当程序员需要增加一个启动器时，需要完成两步操作：   
1、创建启动器实现类，实现 org.nervousync.launcher.StartupLauncher 接口，并在实现类上添加 org.nervousync.annotations.launcher.Launcher 注解，设置好 Launcher 注解的 value 属性。   
2、创建 META-INF/services/org.nervousync.launcher.StartupLauncher 文件，在文件中写明实现类的完整类名（包名+类名）。   
**启动器的管理**
* 通过调用 StartupManager 的 registeredLaunchers 方法，可以获取所有已经注册的启动器配置信息。
* 通过调用 StartupManager 的 config 方法，可以修改已注册启动器的启动类型。
* 通过调用 StartupManager 的 start/stop/restart 方法，可以启动/停止/重启指定的启动器。

## 国际化支持
程序开发过程中，经常会遇到需要将程序移植到不同的语言及地区，这种程序国际化已经成为一种潮流，开发包提供了一套简单易用的方法来完成程序的国际化，包括但不限于提示信息、错误信息、各种界面的文字信息等。
完成程序的国际化最少仅需要两个步骤即可。
### 1. 创建国际化资源文件（必须）
在 META-INF 中创建文件 nervous.i18n，格式如下
```
{
    “groupId”: "{您的组织识别代码}",
    "bundle": "{您的项目识别代码}",
    "errors": [
        {
            "code": "{错误代码 二进制请以0d开头，八进制请以0o开头，16进制请以0x开头}",
            "key": "{错误代码对应的资源信息键值}"
        },
        ...
    ],
    "languages": [
        {
            "code": "{语言代码（例如：en-US）}",
            "name": "{语言名称（例如：English）}",
            "messages": [
                {
                    "key": "{资源信息键值}",
                    "content": "{资源信息英文内容}"
                },
                ...
            ]
        }，
        {
            "code": "{语言代码（例如：zh-CN）}",
            "name": "{语言名称（例如：简体中文）}",
            "messages": [
                {
                    "key": "{资源信息键值}",
                    "content": "{资源信息中文内容}"
                },
                ...
            ]
        }
    ]
}
```

### 2. 在需要的地方添加国际化支持（必须）
在需要进行国际化的位置，使用 MultilingualUtils.findMessage(messageKey, collections) 读取国际化信息并输出。

| 参数名         | 数据类型 | 用途         |
|-------------|------|------------|
| messageKey  | 字符串  | 资源信息键值     |
| collections | 对象数组 | 内容中的可变数据数组 |

如果需要在网页中完成国际化信息的输出，可以使用工具包中包含的JSTL标签库"bean"的 i18n 标签完成国际化信息的读取和输出。

### 3. 向自定义异常添加国际化支持：（可选操作）
将所有自定义异常均继承自org.nervousync.exceptions.AbstractException，
在构造方法中将错误代码传递给org.nervousync.exceptions.AbstractException，
系统会自动读取资源文件中的错误信息，实现异常提示信息的国际化。

**Example:** org.nervousync.exceptions.AbstractException

### 4. 向日志中添加国际化支持（可选操作）
使用 LoggerUtils.Logger 代替原有的日志对象，日志对象兼容slf4j的Logger对象，自动替换原有输出内容为多语言内容。

**Example:** BeanUtils, CertificateUtils 等的LoggerUtils.Logger实例

### 5. 打包时合并资源文件（可选操作）
在多模块开发过程中，需要打包合并国际化资源文件时，需要使用到maven的shade插件，
添加transformer配置使用org.apache.maven.plugins.shade.resource.I18nResourceTransformer
并传入参数”groupId“和”bundle“，资源转换器会自动合并国际化资源文件，并输出到合并打包后的文件中

## 文件操作的扩展
### Zip文件操作
**所在包**: org.nervousync.zip  
开发人员可以使用 ZipFile 创建 zip 文件、将文件添加到 zip 或从 zip 中提取文件。
支持分割存档文件、中日韩注释和入口路径、标准和AES加密/解密数据。

更多使用方法：参见 org.nervousync.test.zip.ZipTest

### 随机操作文件
**类名：** org.nervousync.commons.io.StandardFile   
提供了一个可以随机读取的文件对象，支持本地文件和Samba协议的NAS文件操作。

## 贡献与反馈
欢迎各位朋友将此文档及项目中的提示信息、错误信息等翻译为更多语言，以帮助更多的使用者更好地了解与使用此工具包。   
如果在使用过程中发现问题或需要改进、添加相关功能，请提交issue到本项目或发送电子邮件到[wmkm0113\@gmail.com](mailto:wmkm0113@gmail.com?subject=bugs_and_features)   
为了更好地沟通，请在提交issue或发送电子邮件时，写明如下信息：   
1、目的是：发现Bug/功能改进/添加新功能   
2、请粘贴以下信息（如果存在）：传入数据，预期结果，错误堆栈信息   
3、您认为可能是哪里的代码出现问题（如提供可以帮助我们尽快地找到并解决问题）   
如果您提交的是添加新功能的相关信息，请确保需要添加的功能是一般性的通用需求，即添加的新功能可以帮助到大多数使用者。

如果您需要添加的是定制化的特殊需求，我将收取一定的定制开发费用，具体费用金额根据定制化的特殊需求的工作量进行评估。   
定制化特殊需求请直接发送电子邮件到[wmkm0113\@gmail.com](mailto:wmkm0113@gmail.com?subject=payment_features)，同时请尽量在邮件中写明您可以负担的开发费用预算金额。

## 赞助与鸣谢
<span id="JetBrains">
    <img src="https://resources.jetbrains.com/storage/products/company/brand/logos/jb_beam.png" width="100px" height="100px" alt="JetBrains Logo (Main) logo.">
    <span>非常感谢 <a href="https://www.jetbrains.com/">JetBrains</a> 通过许可证赞助我们的开源项目。</span>
</span>