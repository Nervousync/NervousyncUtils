# Java開發套件

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.nervousync/utils-jdk11/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.nervousync/utils-jdk11/)
[![License](https://img.shields.io/github/license/wmkm0113/utils-jdk11.svg)](https://github.com/wmkm0113/utils-jdk11/blob/mainline/LICENSE)
![Language](https://img.shields.io/badge/language-Java-green)
[![Twitter:wmkm0113](https://img.shields.io/twitter/follow/wmkm0113?label=Follow)](https://twitter.com/wmkm0113)

[English](README.md)
简体中文
[繁體中文](README_zh_TW.md)

Java開發套件是為了提供介面穩定、集成簡單、可重用的工具包，同時優化了協力廠商類庫的引用。工具包中包含了很多經常用到的工具類和功能模組，涵蓋了廣泛的應用場景， 
工具包提供了一套簡潔而強大的API，幫助開發人員更高效地編寫Java代碼，無論是處理日期和時間、字串操作、檔操作或網路請求的發送與處理，還是發送電子郵件、使用SNMP進行性能監控、統一的設定檔管理，
又或者是一次性密碼支援、X.509證書的操作、工作管理員等，該工具包都提供了豐富的模組、功能和方法。

## 目錄
* [JDK版本](#JDK版本)
* [生命週期](#生命週期)
* [使用方法](#使用方法)
* [基礎工具](#基礎工具)
  + [JavaBean工具類](#javabean工具類)
  + [X.509證書工具類](#x509證書工具類)
  + [集合操作工具類](#集合操作工具類)
  + [資料轉換工具類](#資料轉換工具類)
  + [Cookie工具類](#cookie工具類)
  + [隨機ID生成工具類](#隨機ID生成工具類)
  + [圖片工具類](#圖片工具類)
  + [IP地址工具類](#ip地址工具類)
  + [地理座標工具類](#地理座標工具類)
  + [電子郵件工具類](#電子郵件工具類)
  + [一次性密碼工具類](#一次性密碼工具類)
  + [屬性資訊工具類](#屬性資訊工具類)
  + [二進位資料操作工具類](#二進位資料操作工具類)
  + [網路請求工具類](#網路請求工具類)
  + [資料安全工具類](#資料安全工具類)
  + [WebService工具類](#WebService工具類)
  + [字串操作工具類](#字串操作工具類)
  + [資料結構](#資料結構)
* [JavaBean與 XML/JSON/YAML 字串的互相轉換](#javabean與-xmljsonyaml-字串的互相轉換)
* [安全工廠](#安全工廠)
* [設定檔管理員](#設定檔管理員)
* [程式啟動管理器](#程式啟動管理器)
* [國際化支持](#國際化支持)
  + [創建國際化資源檔（必須）](#1-創建國際化資源檔必須)
  + [在需要的地方添加國際化支援（必須）](#2-在需要的地方添加國際化支援必須)
  + [向自訂異常添加國際化支持（可選）](#3-向自訂異常添加國際化支持可選操作)
  + [向日誌中添加國際化支援（可選）](#4-向日誌中添加國際化支援可選操作)
  + [打包時合併資源檔（可選）](#5-打包時合併資源檔可選操作)
* [檔操作的擴展](#檔操作的擴展)
  + [Zip檔操作](#zip檔操作)
  + [隨機操作檔](#隨機操作檔)
* [貢獻與回饋](#貢獻與回饋)
* [贊助與鳴謝](#贊助與鳴謝)

## JDK版本：
**編譯：** OpenJDK 11   
**運行：** OpenJDK 11+ 或相容版本

## 生命週期:
**功能凍結：** 2026年12月31日   
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

## 基礎工具
### JavaBean工具類
**類名** org.nervousync.utils.BeanUtils  
* 根據屬性名稱從來源資料物件複製資料到目標資料物件
* 根據BeanProperty注解從來源資料物件陣列複製資料到目標資料物件
* 根據BeanProperty注解從來源資料物件複製資料到目標資料物件陣列

### X.509證書工具類
**類名** org.nervousync.utils.CertificateUtils  
* 生成金鑰對
* 簽發X.509證書
* 從證書檔、PKCS12檔或二進位資料中讀取X.509證書
* 驗證 X.509 證書的有效期、數位簽章
* 從PKCS12檔或二進位資料中讀取公開金鑰和私密金鑰
* 生成PKCS12檔

### 集合操作工具類
**類名** org.nervousync.utils.CollectionUtils
* 檢查集合是否為空
* 檢查集合是否包含目標物件
* 檢查兩個集合是否包含同一元素
* 檢查集合是否有唯一元素
* 轉換對象為清單
* 合併陣列到清單中
* 合併屬性資訊實例到雜湊表中
* 從集合中尋找第一個符合要求的元素

### 資料轉換工具類
**類名** org.nervousync.utils.ConvertUtils
* 轉換位元組陣列為十六進位字串
* 轉換位元組陣列為字串
* 轉換位元組陣列為實例物件
* 轉換任意實例物件為位元組陣列
* 轉換屬性資訊為資料映射表

### Cookie工具類
**類名** org.nervousync.utils.CookieUtils  
需要添加依賴：
```
<dependency>
    <groupId>jakarta.servlet</groupId>
    <artifactId>jakarta.servlet-api</artifactId>
    <version>5.0.0 or higher</version>
</dependency>
```
* 設置Cookie值
* 讀取Cookie值
* 刪除Cookie值

### 隨機ID生成工具類
**類名** org.nervousync.utils.IDUtils  
* ID生成工具，使用Java SPI註冊生成器實現類。
* 已集成的生成器：UUID 版本1到版本5, 雪花演算法和NanoID.  
**自訂生成器：**   
生成器實現類必須實現介面org.nervousync.generator.IGenerator，
並在META-INF/services資料夾下創建檔案名為org.nervousync.generator.IGenerator的檔，檔中寫明實現類的完整名稱（包名+類名）

### 圖片工具類
**類名** org.nervousync.utils.ImageUtils  
* 讀取圖片的寬度、高度、寬高比
* 圖片操作：剪切、縮放、添加浮水印、計算漢明距離（dHash/pHash）、計算數位簽章（dHash/pHash）

### IP地址工具類
**類名** org.nervousync.utils.IPUtils  
* 根據給定的位址和CIDR，計算IP位址範圍
* 在子網路遮罩和CIDR之間轉換資料
* 在IPv4和IPv6之間轉換資料
* 在IP位址和BigInteger之間轉換資料
* 將壓縮顯示的IPv6位址展開

### 地理座標工具類
**類名** org.nervousync.utils.LocationUtils  
* 在不同坐標系間轉換資料，支援的坐標系：WGS84(GPS)/GCJ02/BD09
* 計算兩個物理座標之間的距離，單位：公里

### 電子郵件工具類
**類名** org.nervousync.utils.MailUtils  
* 發送接收電子郵件（支援協定：IMAP/POP3/SMTP）
* 獲取資料夾中的電子郵件數量
* 列出所有資料夾名稱
* 自動下載電子郵件中包含的附件
* 驗證電子郵件簽名
* 添加電子簽名到郵件

### 一次性密碼工具類
**類名** org.nervousync.utils.OTPUtils  
* 計算一次性密碼演算法的修正時間值
* 生成隨機金鑰
* 生成基於HMAC演算法加密的一次性密碼/基於時間戳記演算法的一次性密碼值
* 驗證基於HMAC演算法加密的一次性密碼/基於時間戳記演算法的一次性密碼值

### 屬性資訊工具類
**類名** org.nervousync.utils.PropertiesUtils  
* 從字串/本地檔/網路檔/輸入流中讀取屬性檔
* 修改屬性檔
* 將屬性檔保存到目標位址

### 二進位資料操作工具類
**類名** org.nervousync.utils.RawUtils  
* 從二進位數字組中讀取boolean/short/int/long/String類型的資料
* 向二進位數字組中寫入boolean/short/int/long/String類型的資料
* 轉換位元組陣列為二進位數字組
* 轉換位元陣列為位元組

### 網路請求工具類
**類名** org.nervousync.utils.RequestUtils
* 解析HTTP方法字串為HttpMethodOption
* 解析功能變數名稱資訊為IP位址
* 讀取和驗證伺服器的SSL證書
* 發送請求並解析回應資料為字串或指定的JavaBean
* 自由轉換查詢字串和參數映射表
* 檢查使用者的角色資訊，使用<code>request.isUserInRole</code>實現
* 支援使用代理伺服器訪問目標位址
* 支持自訂SSL證書進行驗證

### 資料安全工具類
**類名** org.nervousync.utils.SecurityUtils  
* CRC多項式:  CRC-16/ISO-IEC-14443-3-A,CRC-32/JAMCRC,CRC-4/INTERLAKEN,CRC-16/TELEDISK,CRC-32/MPEG-2,CRC-16/GSM,CRC-6/GSM,CRC-7/UMTS,CRC-32/BZIP2,CRC-8/I-CODE,CRC-16/IBM-SDLC,CRC-16/LJ1200,CRC-10/ATM,CRC-8/NRSC-5,CRC-5/USB,CRC-7/ROHC,CRC-12/UMTS,CRC-8/BLUETOOTH,CRC-14/GSM,CRC-8/SMBUS,CRC-8/TECH-3250,CRC-5/G-704,CRC-16/MODBUS,CRC-12/DECT,CRC-7/MMC,CRC-16/CMS,CRC-24/FLEXRAY-A,CRC-24/FLEXRAY-B,CRC-32/ISO-HDLC,CRC-21/CAN-FD,CRC-8/LTE,CRC-15/CAN,CRC-24/LTE-A,CRC-30/CDMA,CRC-3/GSM,CRC-24/LTE-B,CRC-24/OPENPGP,CRC-12/CDMA2000,CRC-16/MAXIM-DOW,CRC-16/XMODEM,CRC-6/G-704,CRC-24/OS-9,CRC-16/DNP,CRC-32/AIXM,CRC-10/CDMA2000,CRC-6/CDMA2000-A,CRC-6/CDMA2000-B,CRC-16/TMS37157,CRC-16/UMTS,CRC-32/XFER,CRC-8/ROHC,CRC-16/DECT-R,CRC-8/WCDMA,CRC-8/DVB-S2,CRC-15/MPT1327,CRC-16/DECT-X,CRC-6/DARC,CRC-16/DDS-110,CRC-32/ISCSI,CRC-16/USB,CRC-8/MIFARE-MAD,CRC-8/AUTOSAR,CRC-16/KERMIT,CRC-16/IBM-3740,CRC-4/G-704,CRC-16/RIELLO,CRC-16/EN-13757,CRC-16/NRSC-5,CRC-14/DARC,CRC-31/PHILIPS,CRC-5/EPC-C1G2,CRC-32/BASE91-D,CRC-16/ARC,CRC-16/MCRF4XX,CRC-16/T10-DIF,CRC-24/INTERLAKEN,CRC-3/ROHC,CRC-13/BBC,CRC-11/UMTS,CRC-16/SPI-FUJITSU,CRC-10/GSM,CRC-8/DARC,CRC-8/OPENSAFETY,CRC-12/GSM,CRC-32/CKSUM,CRC-16/PROFIBUS,CRC-8/GSM-B,CRC-8/GSM-A,CRC-8/SAE-J1850,CRC-8/CDMA2000,CRC-8/MAXIM-DOW,CRC-16/GENIBUS,CRC-8/I-432-1,CRC-17/CAN-FD,CRC-16/OPENSAFETY-B,CRC-32/CD-ROM-EDC,CRC-16/OPENSAFETY-A,CRC-32/AUTOSAR,CRC-16/CDMA2000,CRC-11/FLEXRAY,CRC-24/BLE  
* 摘要演算法: MD5/HmacMD5/SHA1/HmacSHA1/SHA2/HmacSHA2/SHA3/HmacSHA3/SHAKE128/SHAKE256/SM3/HmacSM3  
* 對稱加密演算法: Blowfish/DES/TripleDES/SM4/AES/RC2/RC4/RC5/RC6  
* 非對稱加密演算法: RSA/SM2

### WebService工具類
**類名** org.nervousync.utils.ServiceUtils  
* 生成SOAP請求用戶端
* 生成Restful請求用戶端並處理請求

### 字串操作工具類
**類名** org.nervousync.utils.StringUtils  
* 使用Base32/Base64編碼給定的二進位位元組陣列
* 將給定的Base32/Base64編碼字串解碼為二進位位元組陣列
* 將給定的字串編碼為霍夫曼樹結果實例物件
* 去除字串中的空格
* 檢查給定的字串是否為MD5值/UUID/電話號碼/電子郵寄地址等
* 檢查給定的字串是否為空/非空/包含字串等
* 使用給定的分隔符號分割字串
* 根據規則截取字串
* 驗證給定的字串是否符合代碼類型

### 資料結構
* 霍夫曼樹
* 多叉樹

## JavaBean與 XML/JSON/YAML 字串的互相轉換
任何繼承 org.nervousync.bean.core.BeanObject 的 JavaBean 類都可以輕鬆地在物件實例和 XML/JSON/YAML 字串之間進行轉換。
JavaBean 與 XML 的轉換是通過JAXB實現，與 JSON/YAML 的轉換是通過Jackson實現。   
**1、添加父類**   
開發人員修改需要轉換為 XML/JSON/YAML 字串的JavaBean，使JavaBean繼承 org.nervousync.bean.core.BeanObject 抽象類別。   
**2、添加注解**   
在JavaBean的屬性上添加對應的注解，如果需要轉換為XML，請添加JAXB需要的注解（如：XmlRootElement/XmlElement），或Jackson注解（如JsonProperty）等。   
**3、轉換為 XML/JSON/YAML**   
調用 toXML 方法，將JavaBean實例物件轉換為XML字串。   

| 參數名             | 資料類型 | 用途                                                    |
|-----------------|------|-------------------------------------------------------|
| outputFragment  | 布林值  | 是否輸出XML聲明字串（`<?xml version="1.0" encoding="UTF-8"?>`） |
| formattedOutput | 布林值  | 是否格式化輸出的XML字串                                         |
| encoding        | 字串   | 輸出字串的編碼集（預設為UTF-8）                                    |
調用 toJson 方法，將JavaBean實例物件轉換為JSON字串。或調用 toFormattedJson 方法，將JavaBean實例物件轉換為格式化後的JSON字串。   
調用 toYaml 方法，將JavaBean實例物件轉換為XML字串。或調用 toFormattedYaml 方法，將JavaBean實例物件轉換為格式化後的YAML字串。   
**4、轉換為JavaBean**   
通過調用 org.nervousync.utils.StringUtils 的 stringToObject 靜態方法，可以將字串轉換為JavaBean實例物件。

| 參數名         | 資料類型  | 用途                 |
|-------------|-------|--------------------|
| string      | 字串    | 需要轉換為JavaBean的字串   |
| encoding    | 字串    | 字串的編碼集（預設為UTF-8）   |
| beanClass   | Class | JavaBean的類定義       |
| schemaPaths | 字串陣列  | 用於驗證XML字串的XSD檔路徑陣列 |

通過調用 org.nervousync.utils.StringUtils 的 fileToObject 靜態方法，可以將磁片檔轉換為JavaBean實例物件，檔中的資料類型根據檔副檔名確定。

| 參數名         | 資料類型  | 用途                  |
|-------------|-------|---------------------|
| filePath    | 字串    | 需要轉換為JavaBean的檔存儲路徑 |
| beanClass   | Class | JavaBean的類定義        |
| schemaPaths | 字串陣列  | 用於驗證XML字串的XSD檔路徑陣列  |   
**5、XSD文檔**   
為了驗證XML檔的合法性，最常用的方法是使用XSD文檔來對XML檔進行驗證，程式開發人員可以將XSD文檔存儲到套裝程式中，並通過簡單的配置，讓系統可以找到套裝程式中的XSD文檔。
+ 添加XSD文檔到套裝程式中，並記錄存儲路徑
+ 在META-INF資料夾中創建nervousync.schemas文件，檔案格式為：namespace_uri=對應XSD文檔存儲路徑，如果存在多個XSD文檔定義，則每個XSD映射單獨一行
+ 轉換為JavaBean的方法中，參數 “schemaPaths” 可以為 namespace_uri

## 安全工廠
**類名** org.nervousync.security.factory.SecureFactory   
工具包提供了一個安全工廠類來幫助開發人員保存不同的加密解密配置資訊，方便開發人員對資料進行便捷的加密解密操作。   
**安全工廠初始化**   
安全工廠會自動讀取設定檔，並將安全配置資訊註冊到安全工廠。   
**安全配置的添加**   
調用 SecureFactory 的 registerConfig 靜態方法添加新的安全配置資訊。

| 參數名             | 資料類型               | 用途             |
|-----------------|--------------------|----------------|
| secureName      | 字串                 | 安全配置唯一識別代碼     |
| secureAlgorithm | SecureAlgorithm枚舉值 | 指定加密解密使用的演算法類型 |
**資料加密**   
調用 SecureFactory 的 encrypt 靜態方法完成資料的加密操作，返回加密後的資料。

| 參數名         | 資料類型 | 用途                                 |
|-------------|------|------------------------------------|
| secureName  | 字串   | 安全配置唯一識別代碼（如果為空或未找到，則使用系統安全唯一識別代碼） |
| dataContent | 字串   | 需要加密的資料                            |
**數據解密**   
調用 SecureFactory 的 decrypt 靜態方法完成資料的加密操作，返回加密後的資料。

| 參數名         | 資料類型 | 用途                                 |
|-------------|------|------------------------------------|
| secureName  | 字串   | 安全配置唯一識別代碼（如果為空或未找到，則使用系統安全唯一識別代碼） |
| dataContent | 字串   | 需要解密的資料                            |

## 設定檔管理員
**類名** org.nervousync.configs.ConfigureManager  
在系統開發的過程中，經常會遇到各種不同的設定檔，為了統一對專案中的設定檔進行管理，在開發包中提供了一個設定檔的統一管理器。
開發人員可以通過調用 ConfigureManager 的 getInstance 靜態方法獲取設定檔管理員的實例物件，來進行設定檔的相關操作。   
**管理器的初始化**   
通過調用 ConfigureManager 的 initialize 靜態方法進行設定檔管理員的初始化，開發人員可以通過傳入參數 "customPath" 來設置設定檔的存儲位置。
如果參數 "customPath" 為 null 或空字串，設定檔管理員會在當前使用者的工作目錄下創建名為".configs"的資料夾，並將此資料夾作為預設的設定檔存儲路徑。   
**設定檔的讀取**   
通過調用 ConfigureManager 的 readConfigure 方法讀取設定檔資訊，傳入的參數為設定檔的JavaBean定義類。如果存在同一類型的多個設定檔，可以傳入一個類型為字串的 suffix 參數，用於標識不同的設定檔。   
**設定檔的保存**   
通過調用 ConfigureManager 的 saveConfigure 方法保存設定檔資訊，傳入的參數為設定檔的JavaBean實例物件。如果存在同一類型的多個設定檔，可以傳入一個類型為字串的 suffix 參數，用於標識不同的設定檔。   
**設定檔的移除**
通過調用 ConfigureManager 的 removeConfigure 方法移除設定檔資訊，傳入的參數為設定檔的JavaBean定義類，同時需要傳入一個類型為字串的 suffix 參數，用於移除特定的設定檔。
**注意：** 如果傳入的參數 suffix 為 null 或空字串，則移除指定類型的所有設定檔。
**設定檔的自動載入**
讓需要自動載入設定檔的類繼承 org.nervousync.configs.AutoConfig 抽象類別，在類中添加類型為設定檔類的屬性，並在屬性上添加 org.nervousync.annotations.configs.Configure 注解，
如果此類型的設定檔存在多個，則可以通過 org.nervousync.annotations.configs.Configure 注解的 value 屬性指定使用哪一個設定檔。   
**設定檔的密碼保護**   
在設定檔中總會涉及到各種密碼的保存，為了防止密碼通過設定檔洩露，開發人員可以在設定檔JavaBean定義類的密碼屬性上，添加 org.nervousync.annotations.configs.Password 注解，
通過 org.nervousync.annotations.configs.Password 注解的 value 屬性來指定需要使用的加密方式（通過安全工廠實現），系統會完成純文字密碼在存儲到磁片時自動加密，還可以在從磁片讀取時自動解密。

## 程式啟動管理器
**類名** org.nervousync.launcher.StartupManager   
工具包提供了一個可以自動或手動執行的程式啟動管理器，啟動器使用Java的SPI模式載入所有 org.nervousync.launcher.StartupLauncher 介面的實現類，
並根據實現類上添加的 org.nervousync.annotations.launcher.Launcher 注解的 value 屬性值，進行啟動器的執行。   
org.nervousync.annotations.launcher.Launcher 注解的 value 屬性值為啟動類型的枚舉值，允許的值為 AUTO（自動）/MANUAL（手動）/DISABLE（禁用）。
程式開發人員需要使用程式啟動管理器時，需要顯式調用 org.nervousync.launcher.StartupManager 的 initialize 靜態方法，工具包會自動掃描並載入所有啟動器，並在完成載入後，自動啟動類型為 AUTO（自動）的啟動器。
程式啟動管理器在初始化時會在系統中註冊鉤副程式，當主程序正常退出時，會自動執行程式啟動管理器的 destroy 方法，關閉所有正在運行的啟動器。   
**啟動器的開發**   
當程式師需要增加一個啟動器時，需要完成兩步操作：   
1、創建啟動器實現類，實現 org.nervousync.launcher.StartupLauncher 介面，並在實現類上添加 org.nervousync.annotations.launcher.Launcher 注解，設置好 Launcher 注解的 value 屬性。   
2、創建 META-INF/services/org.nervousync.launcher.StartupLauncher 檔，在檔中寫明實現類的完整類名（包名+類名）。   
**啟動器的管理**
* 通過調用 StartupManager 的 registeredLaunchers 方法，可以獲取所有已經註冊的啟動器配置資訊。
* 通過調用 StartupManager 的 config 方法，可以修改已註冊啟動器的啟動類型。
* 通過調用 StartupManager 的 start/stop/restart 方法，可以啟動/停止/重啟指定的啟動器。

## 國際化支持
程式開發過程中，經常會遇到需要將程式移植到不同的語言及地區，這種程式國際化已經成為一種潮流，開發包提供了一套簡單易用的方法來完成程式的國際化，包括但不限於提示資訊、錯誤資訊、各種介面的文字資訊等。
完成程式的國際化最少僅需要兩個步驟即可。
### 1. 創建國際化資源檔（必須）
在 META-INF 中創建文件 nervous.i18n，格式如下
```
{
    “groupId”: "{您的組織識別代碼}",
    "bundle": "{您的專案識別代碼}",
    "errors": [
        {
            "code": "{錯誤代碼 二進位請以0d開頭，八進制請以0o開頭，16進制請以0x開頭}",
            "key": "{錯誤代碼對應的資源資訊鍵值}"
        },
        ...
    ],
    "languages": [
        {
            "code": "{語言代碼（例如：en-US）}",
            "name": "{語言名稱（例如：English）}",
            "messages": [
                {
                    "key": "{資源資訊鍵值}",
                    "content": "{資源資訊英文內容}"
                },
                ...
            ]
        }，
        {
            "code": "{語言代碼（例如：zh-CN）}",
            "name": "{語言名稱（例如：簡體中文）}",
            "messages": [
                {
                    "key": "{資源資訊鍵值}",
                    "content": "{資源資訊中文內容}"
                },
                ...
            ]
        }
    ]
}
```

### 2. 在需要的地方添加國際化支援（必須）
在需要進行國際化的位置，使用 MultilingualUtils.findMessage(messageKey, collections) 讀取國際化資訊並輸出。

| 參數名         | 資料類型 | 用途         |
|-------------|------|------------|
| messageKey  | 字串   | 資源資訊鍵值     |
| collections | 物件陣列 | 內容中的可變資料陣列 |

如果需要在網頁中完成國際化資訊的輸出，可以使用工具包中包含的JSTL標籤庫"bean"的 i18n 標籤完成國際化資訊的讀取和輸出。

### 3. 向自訂異常添加國際化支持：（可選操作）
將所有自訂異常均繼承自org.nervousync.exceptions.AbstractException，
在構造方法中將錯誤代碼傳遞給org.nervousync.exceptions.AbstractException，
系統會自動讀取資源檔中的錯誤資訊，實現異常提示資訊的國際化。

**Example:** org.nervousync.exceptions.AbstractException

### 4. 向日誌中添加國際化支援（可選操作）
使用 LoggerUtils.Logger 代替原有的日誌物件，日誌物件相容slf4j的Logger物件，自動替換原有輸出內容為多語言內容。

**Example:** BeanUtils, CertificateUtils 等的LoggerUtils.Logger實例

### 5. 打包時合併資源檔（可選操作）
在多模組開發過程中，需要打包合併國際化資源檔時，需要使用到maven的shade外掛程式，
添加transformer配置使用org.apache.maven.plugins.shade.resource.I18nResourceTransformer
並傳入參數”groupId“和”bundle“，資源轉換器會自動合併國際化資源檔，並輸出到合併打包後的檔中

## 檔操作的擴展
### Zip檔操作
**所在包**: org.nervousync.zip  
開發人員可以使用 ZipFile 創建 zip 檔、將檔添加到 zip 或從 zip 中提取文件。
支援分割存檔檔、中日韓注釋和入口路徑、標準和AES加密/解密資料。

更多使用方法：參見 org.nervousync.test.zip.ZipTest

### 隨機操作檔
**類名：** org.nervousync.commons.io.StandardFile   
提供了一個可以隨機讀取的檔物件，支援本地檔和Samba協定的NAS檔操作。

## 貢獻與回饋
歡迎各位朋友將此文檔及專案中的提示資訊、錯誤資訊等翻譯為更多語言，以説明更多的使用者更好地瞭解與使用此工具包。   
如果在使用過程中發現問題或需要改進、添加相關功能，請提交issue到本專案或發送電子郵件到[wmkm0113\@gmail.com](mailto:wmkm0113@gmail.com?subject=bugs_and_features)   
為了更好地溝通，請在提交issue或發送電子郵件時，寫明如下資訊：   
1、目的是：發現Bug/功能改進/添加新功能   
2、請粘貼以下資訊（如果存在）：傳入資料，預期結果，錯誤堆疊資訊   
3、您認為可能是哪裡的代碼出現問題（如提供可以幫助我們儘快地找到並解決問題）   
如果您提交的是添加新功能的相關資訊，請確保需要添加的功能是一般性的通用需求，即添加的新功能可以幫助到大多數使用者。

如果您需要添加的是定制化的特殊需求，我將收取一定的定制開發費用，具體費用金額根據定制化的特殊需求的工作量進行評估。   
定制化特殊需求請直接發送電子郵件到[wmkm0113\@gmail.com](mailto:wmkm0113@gmail.com?subject=payment_features)，同時請儘量在郵件中寫明您可以負擔的開發費用預算金額。

## 贊助與鳴謝
<span id="JetBrains">
    <img src="https://resources.jetbrains.com/storage/products/company/brand/logos/jetbrains.svg" height="40px" alt="JetBrains Logo (Main) logo.">
    <span>非常感謝 <a href="https://www.jetbrains.com/">JetBrains</a> 通過許可證贊助我們的開源項目。</span>
</span>
