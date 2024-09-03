package org.nervousync.annotations.beans;

import org.nervousync.commons.Globals;
import org.nervousync.utils.StringUtils;

import java.lang.annotation.*;

/**
 * <h2 class="en-US">Annotation for data output config</h2>
 * <span class="en-US">Configure output data type, formatted output string and string encoding</span>
 * <h2 class="zh-CN">标注用于数据输出的配置</h2>
 * <span class="en-US">定义输出的数据类型，是否格式化输出的字符串以及输出字符串的编码集</span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Apr 15, 2023 14:27:15 $
 */
@Inherited
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
public @interface OutputConfig {

	/**
	 * <h3 class="en-US">Output string type</h3>
	 * <span class="en-US">Default is SIMPLE, base64 encoded byte arrays. Other types: JSON/XML/YAML</span>
	 * <h3 class="zh-CN">输出字符串类型</h3>
	 * <span class="zh-CN">默认值为SIMPLE，使用Base64编码的字节数组。可选类型包括：JSON/XML/YAML</span>
	 *
	 * @return <span class="en-US">Enumeration value type of StringUtils.StringType</span>
	 * <span class="zh-CN">StringUtils.StringType枚举类型</span>
	 * @see org.nervousync.utils.StringUtils.StringType
	 */
	StringUtils.StringType type() default StringUtils.StringType.SERIALIZABLE;

	/**
	 * <h3 class="en-US">Format output string status</h3>
	 * <span class="en-US"><code>true</code> for format output string, eg: add break line, add indent etc., <code>false</code> for output string in one line</span>
	 * <h3 class="en-US">格式化输出字符串状态</h3>
	 * <span class="en-US"><code>true</code>格式化输出的字符串，添加换行及缩进等。<code>false</code>在同一行输出所有数据</span>
	 *
	 * @return <span class="en-US">Formatted status</span>
	 * <span class="zh-CN">格式化输出状态</span>
	 */
	boolean formatted() default false;

	/**
	 * <h3 class="en-US">Output string encoding</h3>
	 * <span class="en-US">Default is UTF-8</span>
	 * <h3 class="zh-CN">输出字符串编码集</h3>
	 * <span class="zh-CN">默认值为UTF-8</span>
	 *
	 * @return <span class="en-US">String encoding</span>
	 * <span class="zh-CN">字符串编码集</span>
	 */
	String encoding() default Globals.DEFAULT_ENCODING;

}
