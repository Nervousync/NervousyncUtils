# Java Development Toolkit

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.nervousync/utils-jdk11/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.nervousync/utils-jdk11/)
[![License](https://img.shields.io/github/license/wmkm0113/utils-jdk11.svg)](https://github.com/wmkm0113/utils-jdk11/blob/mainline/LICENSE)
![Language](https://img.shields.io/badge/language-Java-green)
[![Twitter:wmkm0113](https://img.shields.io/twitter/follow/wmkm0113?label=Follow)](https://twitter.com/wmkm0113)

English
[简体中文](README_zh_CN.md)
[繁體中文](README_zh_TW.md)

The Java development toolkit is designed to provide a toolkit with stable interfaces, simple integration, and reusable, while optimizing the reference of third-party class libraries. The toolkit contains many frequently used tool classes and functional modules, covering a wide range of application scenarios.
The toolkit provides a set of concise and powerful APIs to help developers write Java code more efficiently, whether it is processing date and time, string operations, file operations or sending and processing of network requests, or sending emails or using SNMP Perform performance monitoring and unified configuration file management,
Or one-time password support, X.509 certificate operation, task manager, etc., the toolkit provides a wealth of modules, functions and methods.

## Table of contents
* [JDK Version](#jdk-version)
* [End of Life](#end-of-life)
* [Usage](#usage)
* [Basic Utilities](#basic-utilities)
  + [JavaBean utilities](#javabean-utilities)
  + [X.509 certificate utilities](#x509-certificate-utilities)
  + [Collection utilities](#collection-utilities)
  + [Data convert utilities](#data-convert-utilities)
  + [Cookie utilities](#cookie-utilities)
  + [Random ID generator utilities](#random-id-generator-utilities)
  + [Image utilities](#image-utilities)
  + [IP address convert utilities](#ip-address-convert-utilities)
  + [Geographically coordinates utilities](#geographically-coordinates-utilities)
  + [E-Mail utilities](#e-mail-utilities)
  + [One-Time password utilities](#one-time-password-utilities)
  + [Properties utilities](#properties-utilities)
  + [Raw data operate utilities](#raw-data-operate-utilities)
  + [Http/Https request utilities](#httphttps-request-utilities)
  + [Data security utilities](#data-security-utilities)
  + [WebService utilities](#webservice-utilities)
  + [String operate utilities](#string-operate-utilities)
  + [Data struct](#data-struct)
* [Convert between JavaBean and XML/JSON/YAML string](#convert-between-javabean-and-xmljsonyaml-string)
* [Secure factory](#secure-factory)
* [Configure file manager](#configure-file-manager)
* [Startup manager](#startup-manager)
* [Internationalize(i18n) Support](#internationalizei18n-support)
  + [Create i18n resource file (Required)](#1-create-i18n-resource-file-required)
  + [Add internationalize support for anything (Required)](#2-add-internationalize-support-for-anything-required)
  + [Add internationalize support for exceptions: (Optional)](#3-add-internationalize-support-for-exceptions-optional)
  + [Add internationalize support for logger: (Optional)](#4-add-internationalize-support-for-logger-optional)
  + [Merge resource files when packaging: (optional operation)](#5-merge-resource-files-when-packaging-optional-operation)
* [Extension the file operate](#extension-the-file-operate)
  + [Zip file operate](#zip-file-operate)
  + [Random access file operates](#random-access-file-operates)
* [Contributions and feedback](#contributions-and-feedback)
* [Sponsorship and Thanks To](#sponsorship-and-thanks-to)

## JDK Version：
**Compile:** OpenJDK 11   
**Runtime：** OpenJDK 11+ or compatible version

## End of Life:
**Features Freeze:** 31, Dec, 2026   
**Secure Patch:** 31, Dec, 2029

## Usage
**Maven:**
```
<dependency>
    <groupId>org.nervousync</groupId>
	<artifactId>utils-jdk11</artifactId>
    <version>${version}</version>
</dependency>
```
**Gradle:**
```
Manual: compileOnly group: 'org.nervousync', name: 'utils-jdk11', version: '${version}'
Short: compileOnly 'org.nervousync:utils-jdk11:${version}'
```
**SBT:**
```
libraryDependencies += "org.nervousync" % "utils-jdk11" % "${version}" % "provided"
```
**Ivy:**
```
<dependency org="org.nervousync" name="utils-jdk11" rev="${version}"/>
```

## Basic Utilities
### JavaBean utilities
**Class name**: org.nervousync.utils.BeanUtils  
* Copy object fields value from the source object to the target object, based field name
* Copy object fields value from the source object array to the target object, based annotation: BeanProperty
* Copy object fields value from the source object to the target object arrays, based annotation: BeanProperty

### X.509 certificate utilities
**Class name**: org.nervousync.utils.CertificateUtils  
* Generate Keypair
* Signature and generate X.509 certificate
* Parse X.509 certificate from certificate file, PKCS12 file or binary data arrays
* Validate X.509 certificate period and signature
* Read PublicKey/PrivateKey from binary data arrays or PKCS12 file
* Signature and generate PKCS12 file

### Collection utilities
**Class name**: org.nervousync.utils.CollectionUtils
* Check collection is empty
* Check collection contains target element
* Check two collections contain the same element
* Check collection contains unique element
* Convert the object to an array list
* Merge array to list
* Merge properties to map
* Find the first match element of collections

### Data convert utilities
**Class name**: org.nervousync.utils.ConvertUtils
* Convert data bytes to hex string
* Convert data bytes to string
* Convert data bytes to Object
* Convert any to data bytes
* Convert properties to data map

### Cookie utilities
**Class name**: org.nervousync.utils.CookieUtils  
Dependency required:
```
<dependency>
    <groupId>jakarta.servlet</groupId>
	<artifactId>jakarta.servlet-api</artifactId>
    <version>5.0.0 or higher</version>
</dependency>
```
* Setting cookie value
* Read cookie value
* Delete cookie value

### Random ID generator utilities
**Class name**: org.nervousync.utils.IDUtils  
* ID generator utils, register generator implements class by Java SPI.
* Embedded generator: UUID version 1 to version 5, Snowflake and NanoID.  
**Customize generator:**   
Generator class must implement interface org.nervousync.generator.IGenerator
and create file named: org.nervousync.generator.IGenerator save to META-INF/services

### Image utilities
**Class name**: org.nervousync.utils.ImageUtils  
* Read image width (px), height (px), ratio (width/height). 
* Image operator: cut, resize and add watermark, calculate hamming (dHash/pHash), calculate signature (dHash/pHash)

### IP address convert utilities
**Class name**: org.nervousync.utils.IPUtils  
* Calculate IP range by given address and CIDR value
* Convert between netmask address and CIDR value
* Convert between IPv4 and IPv6
* Convert between IP address and BigInteger(for support IPv6)
* Expand the combo IPv6 address

### Geographically coordinates utilities
**Class name**: org.nervousync.utils.LocationUtils  
* Convert GeoPoint at WGS84(GPS)/GCJ02/BD09
* Calculate the distance of two given geography point. (Unit: Kilometers)

### E-Mail utilities
**Class name**: org.nervousync.utils.MailUtils  
* Send/Receive email (Support protocols: IMAP/POP3/SMTP)
* Count email in folder
* List folder names
* Download email attachment files automatically
* Verify email signature
* Add signature to email

### One-Time password utilities
**Class name**: org.nervousync.utils.OTPUtils  
* Calculate OTP fixed time value
* Generate random key
* Generate TOTP/HOTP Code
* Verify TOTP/HOTP Code

### Properties utilities
**Class name**: org.nervousync.utils.PropertiesUtils  
* Read properties from string/file path/URL instance/input stream
* Modify properties file
* Storage properties instance to the target file path

### Raw data operate utilities
**Class name**: org.nervousync.utils.RawUtils  
* Read boolean/short/int/long/String from binary data bytes
* Write boolean/short/int/long/String into binary data bytes
* Convert the char array to binary data bytes
* Convert the bit array to byte

### Http/Https request utilities
**Class name**: org.nervousync.utils.RequestUtils
* Parse http method string to HttpMethodOption
* Resolve domain name to IP address
* Retrieve and verify SSL certificate from server
* Send request and parse response content to target JavaBean or string
* Convert data between query string and parameter map
* Check user role code using <code>request.isUserInRole</code>
* Support using proxy server to request target address
* Support custom SSL certificate verify

### Data security utilities
**Class name**: org.nervousync.utils.SecurityUtils  
* CRC polynomial:  CRC-16/ISO-IEC-14443-3-A,CRC-32/JAMCRC,CRC-4/INTERLAKEN,CRC-16/TELEDISK,CRC-32/MPEG-2,CRC-16/GSM,CRC-6/GSM,CRC-7/UMTS,CRC-32/BZIP2,CRC-8/I-CODE,CRC-16/IBM-SDLC,CRC-16/LJ1200,CRC-10/ATM,CRC-8/NRSC-5,CRC-5/USB,CRC-7/ROHC,CRC-12/UMTS,CRC-8/BLUETOOTH,CRC-14/GSM,CRC-8/SMBUS,CRC-8/TECH-3250,CRC-5/G-704,CRC-16/MODBUS,CRC-12/DECT,CRC-7/MMC,CRC-16/CMS,CRC-24/FLEXRAY-A,CRC-24/FLEXRAY-B,CRC-32/ISO-HDLC,CRC-21/CAN-FD,CRC-8/LTE,CRC-15/CAN,CRC-24/LTE-A,CRC-30/CDMA,CRC-3/GSM,CRC-24/LTE-B,CRC-24/OPENPGP,CRC-12/CDMA2000,CRC-16/MAXIM-DOW,CRC-16/XMODEM,CRC-6/G-704,CRC-24/OS-9,CRC-16/DNP,CRC-32/AIXM,CRC-10/CDMA2000,CRC-6/CDMA2000-A,CRC-6/CDMA2000-B,CRC-16/TMS37157,CRC-16/UMTS,CRC-32/XFER,CRC-8/ROHC,CRC-16/DECT-R,CRC-8/WCDMA,CRC-8/DVB-S2,CRC-15/MPT1327,CRC-16/DECT-X,CRC-6/DARC,CRC-16/DDS-110,CRC-32/ISCSI,CRC-16/USB,CRC-8/MIFARE-MAD,CRC-8/AUTOSAR,CRC-16/KERMIT,CRC-16/IBM-3740,CRC-4/G-704,CRC-16/RIELLO,CRC-16/EN-13757,CRC-16/NRSC-5,CRC-14/DARC,CRC-31/PHILIPS,CRC-5/EPC-C1G2,CRC-32/BASE91-D,CRC-16/ARC,CRC-16/MCRF4XX,CRC-16/T10-DIF,CRC-24/INTERLAKEN,CRC-3/ROHC,CRC-13/BBC,CRC-11/UMTS,CRC-16/SPI-FUJITSU,CRC-10/GSM,CRC-8/DARC,CRC-8/OPENSAFETY,CRC-12/GSM,CRC-32/CKSUM,CRC-16/PROFIBUS,CRC-8/GSM-B,CRC-8/GSM-A,CRC-8/SAE-J1850,CRC-8/CDMA2000,CRC-8/MAXIM-DOW,CRC-16/GENIBUS,CRC-8/I-432-1,CRC-17/CAN-FD,CRC-16/OPENSAFETY-B,CRC-32/CD-ROM-EDC,CRC-16/OPENSAFETY-A,CRC-32/AUTOSAR,CRC-16/CDMA2000,CRC-11/FLEXRAY,CRC-24/BLE  
* Digest provider: MD5/HmacMD5/SHA1/HmacSHA1/SHA2/HmacSHA2/SHA3/HmacSHA3/SHAKE128/SHAKE256/SM3/HmacSM3  
* Symmetric provider: Blowfish/DES/TripleDES/SM4/AES/RC2/RC4/RC5/RC6  
* Asymmetric provider: RSA/SM2

### WebService utilities
**Class name**: org.nervousync.utils.ServiceUtils  
* Generate SOAP Client instance
* Generate Restful Client and process request

### String operate utilities
**Class name**: org.nervousync.utils.StringUtils  
* Encode byte arrays using Base32/Base64
* Decode Base32/Base64 string to byte arrays
* Encode string to a Huffman tree
* Trim given string
* Match given string is MD5 value/UUID/phone number/e-mail address etc.
* Check given string is empty/notNull/notEmpty/contains string etc.
* Tokenize string by given delimiters
* Substring given input string by rule
* Validate given string is match code type

### Data struct
* Huffman Tree support
* Multiway Tree support

## Convert between JavaBean and XML/JSON/YAML string
Any JavaBean class that extends org.nervousync.bean.core.BeanObject can easily convert between object instances and XML/JSON/YAML strings.
Toolkit using JAXB to implement convert between JavaBean and XML string, using Jackson to implement convert between JavaBean and JSON/YAML string.   
**1.Add parent class**   
Developers modify the JavaBean that needs to be converted to XML/JSON/YAML strings so that the JavaBean extends the org.nervousync.bean.core.BeanObject abstract class.   
**2.Add annotations**   
Add corresponding annotations to the properties of the JavaBean. If you need to convert it to XML, please add the annotations required by JAXB (such as XmlRootElement/XmlElement), 
if you need to convert it to JSON/YAML, please add the annotations required by Jackson annotations (such as JsonProperty), etc.   
**3.Convert to XML/JSON/YAML**   
Call the toXML method to convert the JavaBean instance object into an XML string.   

| Parameter       | Data type | Notes                                                                              |
|-----------------|-----------|------------------------------------------------------------------------------------|
| outputFragment  | boolean   | Whether to output XML declaration string(`<?xml version="1.0" encoding="UTF-8"?>`) |
| formattedOutput | boolean   | Whether to format the output XML string                                            |
| encoding        | String    | The encoding set of the output string (Default: UTF-8)                             |
Call the toJson method to convert the JavaBean instance object into a JSON string. Or call the toFormattedJson method to convert the JavaBean instance object into a formatted JSON string.   
Call the toYaml method to convert the JavaBean instance object into an XML string. Or call the toFormattedYaml method to convert the JavaBean instance object into a formatted YAML string.   
**4.Convert to JavaBean**   
A string can be converted to a JavaBean instance object by calling the stringToObject static method of org.nervousync.utils.StringUtils.

| Parameter   | Data type    | Notes                                              |
|-------------|--------------|----------------------------------------------------|
| string      | String       | String that needs to be converted to JavaBean      |
| encoding    | String       | string encoding set (Default: UTF-8)               |
| beanClass   | Class        | JavaBean class definition                          |
| schemaPaths | String array | Array of XSD file paths for validating XML strings |

By calling the fileToObject static method of org.nervousync.utils.StringUtils, the disk file can be converted into a JavaBean instance object. The data type in the file is determined according to the file extension.

| Parameter   | Data type    | Notes                                                    |
|-------------|--------------|----------------------------------------------------------|
| filePath    | String       | File storage path that needs to be converted to JavaBean |
| beanClass   | Class        | JavaBean class definition                                |
| schemaPaths | String array | Array of XSD file paths for validating XML strings       |   
**5.XSD documents**   
To verify the legitimacy of XML files, the most common method is to use XSD documents to verify XML files. Program developers can store XSD documents into the program package, and through simple configuration, the system can find the XSD document.
+ Add the XSD document to the package and record the storage path
+ Create the nerveync.schemas file in the META-INF folder. The file format is: `namespace_uri`=`record the XSD document storage path`. If there are multiple XSD document definitions, each XSD mapping has a separate line.
+ In the method converted to JavaBean, the parameter "schemaPaths" can be namespace_uri

## Secure factory
**Class name** org.nervousync.security.factory.SecureFactory   
The toolkit provides a security factory class to help developers save different encryption and decryption configuration information, so that developers can perform convenient encryption and decryption operations on data.      
**Secure factory initialize**   
The security factory will automatically read the configuration file and register the security configuration information to the security factory.   
**Add secure configure**   
Call the registerConfig static method of SecureFactory to add new security configuration information.

| Parameter       | Data type                             | Notes                                                         |
|-----------------|---------------------------------------|---------------------------------------------------------------|
| secureName      | String                                | Identification code of secure configure                       |
| secureAlgorithm | Enumeration value of secure algorithm | Specify the algorithm type used for encryption and decryption |
**Encrypt data**   
Call the encrypt static method of SecureFactory to complete the data encryption operation and return the encrypted data.

| Parameter   | Data type | Notes                                                                                                |
|-------------|-----------|------------------------------------------------------------------------------------------------------|
| secureName  | String    | Identification code of secure configure (If code is null or not found, using system default instead) |
| dataContent | String    | Data that needs to be encrypted                                                                      |
**Decrypt data**   
Call the decrypt static method of SecureFactory to complete the data decryption operation and return the decrypted data.

| Parameter   | Data type | Notes                                                                                                |
|-------------|-----------|------------------------------------------------------------------------------------------------------|
| secureName  | String    | Identification code of secure configure (If code is null or not found, using system default instead) |
| dataContent | String    | Data that needs to be decrypted                                                                      |

## Configure file manager
**Class name** org.nervousync.configs.ConfigureManager  
In the process of system development, we often encounter various configuration files. To uniformly manage the configuration files in the project, a unified manager of configuration files is provided in the development package.
Developers can obtain the instance object of the configuration file manager by calling the getInstance static method of ConfigureManager to perform configuration file related operations.   
**Manager initialize**   
By calling the initialize static method of ConfigureManager to initialize the configuration file manager, developers can set the storage location of the configuration file by passing in the parameter "customPath".
If the parameter "customPath" is null or an empty string, the profile manager will create a folder named ".configs" in the current user's working directory and use this folder as the default configuration file storage path.   
**Read configure file**   
Read the configuration file information by calling the readConfigure method of ConfigureManager, and the passed-in parameter is the JavaBean definition class of the configuration file. 
If there are multiple configuration files of the same type, you can pass in a suffix parameter of type string to identify different configuration files.   
**Save configure file**   
Save the configuration file information by calling the saveConfigure method of ConfigureManager. The parameter passed in is the JavaBean instance object of the configuration file. 
If there are multiple configuration files of the same type, you can pass in a suffix parameter of type string to identify different configuration files.   
**Remove configure file**
Remove configuration file information by calling the removeConfigure method of ConfigureManager. The passed-in parameter is the JavaBean definition class of the configuration file. 
At the same time, a suffix parameter of type string needs to be passed in to remove a specific configuration file.
**Notice:** If the passed parameter suffix is null or an empty string, all configuration files of the specified type will be removed.
**Load configure file automatically**
Let the class that needs to automatically load the configuration file inherit the org.nervousync.configs.AutoConfig abstract class, add an attribute of type configuration file class to the class, and add the org.nervousync.annotations.configs.Configure annotation to the attribute.
If there are multiple configuration files of this type, you can specify which configuration file to use through the value attribute of the org.nervousync.annotations.configs.Configure annotation.   
**Password protection of configuration files**   
The configuration file always involves the saving of various passwords. To prevent passwords from being leaked through the configuration file, developers can add the org.nervousync.annotations.configs.Password annotation to the password attribute of the JavaBean definition class in the configuration file.
Use the value attribute of the org.nervousync.annotations.configs.Password annotation to specify the encryption method to be used (implemented through the security factory). The system will automatically encrypt the plaintext password when it is stored on the disk, and can also automatically decrypt it when reading it from the disk.

## Startup manager
**Class name** org.nervousync.launcher.StartupManager   
The toolkit provides a program startup manager that can be executed automatically or manually. The launcher uses Java's SPI mode to load all implementation classes of the org.nervousync.launcher.StartupLauncher interface.
And execute the launcher based on the value attribute value of the org.nervousync.annotations.launcher.Launcher annotation added on the implementation class.   
The value attribute value of the org.nervousync.annotations.launcher.Launcher annotation is the enumeration value of the launch type. The allowed value is AUTO/MANUAL/DISABLE.
When program developers need to use the program startup manager, they need to explicitly call the initialize static method of org.nervousync.launcher.StartupManager. The toolkit will automatically scan and load all launchers, and after completing the loading, the automatic startup type is AUTO starter.
The program startup manager will register a hook program in the system during initialization. When the main program exits normally, the destroy method of the program startup manager will be automatically executed to close all running launchers.   
**Developer startup launcher**   
When programmers need to add a launcher, they need to complete two steps:   
1.Create a launcher implementation class, implement the org.nervousync.launcher.StartupLauncher interface, add the org.nervousync.annotations.launcher.Launcher annotation to the implementation class, and set the value attribute of the Launcher annotation.
2.Create the META-INF/services/org.nervousync.launcher.StartupLauncher file and write the complete class name of the implementation class (package name + class name) in the file.    
**Manage startup launcher**
* By calling the registeredLaunchers method of StartupManager, you can obtain the configuration information of all registered launchers.
* The startup type of registered launcher can be modified by calling the config method of StartupManager.
* By calling the start/stop/restart method of StartupManager, you can start/stop/restart the specified starter.

## Internationalize(i18n) Support
In the process of program development, we often encounter the need to transplant programs to different languages and regions. 
This kind of program internationalization has become a trend. The development kit provides a set of simple and easy-to-use methods to complete the internationalization of programs, including, 
But it is not limited to prompt information, error information, text information on various interfaces, etc.
Completing the internationalization of a program requires at least two steps.
### 1. Create i18n resource file (Required)
Create nervousync.i18n file in META-INF
```
{
    “groupId”: "{Your origanization id}",
    "bundle": "{Your project code}",
    "errors": [
        {
            "code": "{Error code, binary string must begin as '0d', octal string must begin as '0o', hexadecimal string must begin as '0x'}",
            "key": "{Error message key}"
        },
        ...
    ],
    "languages": [
        {
            "code": "{Language code(Example: en-US)}",
            "name": "{Language name(Example: English)}",
            "messages": [
                {
                    "key": "{Message key}",
                    "content": "{Message content in English}"
                },
                ...
            ]
        }，
        {
            "code": "{Language code(Example: zh-CN)}",
            "name": "{Language name(Example: 简体中文)}",
            "messages": [
                {
                    "key": "{Message key}",
                    "content": "{Message content in Chinese}"
                },
                ...
            ]
        }
    ]
}
```

### 2. Add internationalize support for anything (Required)
Using MultilingualUtils.findMessage(bundle, messageKey, collections) to retrieve the multilingual message which will output

| Parameter   | Data type    | Notes                          |
|-------------|--------------|--------------------------------|
| messageKey  | String       | Resource information key value |
| collections | Object array | Mutable data array in content  |

If you need to complete the output of internationalization information in a web page, 
you can use the i18n tag of the JSTL tag library "bean" included in the toolkit to complete the reading and output of internationalization information.

### 3. Add internationalize support for exceptions: (Optional)
Modify all Custom exception class, let custom exception extends org.nervousync.exceptions.AbstractException
Please transfer the error code to the org.nervousync.exceptions.AbstractException at constructor of custom exception,
The system will automatically read the error information in the resource file and realize the internationalization of exception prompt information.

**Example:** org.nervousync.exceptions.AbstractException

### 4. Add internationalize support for logger: (Optional)
Using LoggerUtils.Logger instead all the logger instance, 
logger instance was compatible with the Logger of slf4j, 
logger instance will replace the log content to multilingual automatically

**Example:** LoggerUtils.Logger instance in BeanUtils, CertificateUtils etc.

### 5. Merge resource files when packaging: (optional operation)
In the multi-module development process, when you need to package and merge international resource files, you need to use the maven shade plug-in.
Add transformer configuration using org.apache.maven.plugins.shade.resource.I18nResourceTransformer
And pass in the parameters "groupId" and "bundle", the resource converter will automatically merge the internationalized resource files and output them to the merged and packaged file.

## Extension the file operate
### Zip file operate
**Package**: org.nervousync.zip  
Developers can use ZipFile to create zip file, add file to zip or extract file from zip.
Supported split archive file, Chinese/Japanese/Korean comment and entry path, standard and AES encrypt/decrypt data.

More usages: See org.nervousync.test.zip.ZipTest

### Random access file operates
**Class name:** org.nervousync.commons.io.StandardFile   
Provides a file object that can be read randomly and supports local file and NAS file operations of the Samba protocol.

## Contributions and feedback
Friends are welcome to translate the prompt information, error messages, 
etc. in this document and project into more languages to help more users better understand and use this toolkit.   
If you find problems during use or need to improve or add related functions, 
please submit an issue to this project or send email to [wmkm0113\@gmail.com](mailto:wmkm0113@gmail.com?subject=bugs_and_features)   
For better communication, please include the following information when submitting an issue or sending an email:
1. The purpose is: discover bugs/function improvements/add new features   
2. Please paste the following information (if it exists): incoming data, expected results, error stack information   
3. Where do you think there may be a problem with the code (if provided, it can help us find and solve the problem as soon as possible)

If you are submitting information about adding new features, please ensure that the features to be added are general needs, that is, the new features can help most users.

If you need to add customized special requirements, I will charge a certain custom development fee.
The specific fee amount will be assessed based on the workload of the customized special requirements.   
For customized special features, please send an email directly to [wmkm0113\@gmail.com](mailto:wmkm0113@gmail.com?subject=payment_features). At the same time, please try to indicate the budget amount of development cost you can afford in the email.

## Sponsorship and Thanks To
<span id="JetBrains">
    <img src="https://resources.jetbrains.com/storage/products/company/brand/logos/jb_beam.png" width="100px" height="100px" alt="JetBrains Logo (Main) logo.">
    <span>Many thanks to <a href="https://www.jetbrains.com/">JetBrains</a> for sponsoring our Open Source projects with a license.</span>
</span>