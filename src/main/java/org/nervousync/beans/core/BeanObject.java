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
package org.nervousync.beans.core;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlTransient;
import org.nervousync.annotations.beans.OutputConfig;
import org.nervousync.commons.Globals;
import org.nervousync.utils.*;

import java.io.*;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * <h2 class="en-US">Abstract class of JavaBean</h2>
 * <span class="en-US">
 * If JavaBean class extends the current abstract class, it's can easier convert object to JSON/XML/YAML string.
 * Default encoding is UTF-8
 * Convert object to XML must add annotation to class and fields, using JAXB annotation
 * Convert custom fields in object to JSON/YAML must add annotation to fields, using jackson annotation
 * </span>
 * <h2 class="zh-CN">JavaBean的抽象类</h2>
 * <span class="zh-CN">
 * <p>如果JavaBean类继承此抽象类，将可以简单的转化对象为JSON/XML/YAML字符串。默认编码集为UTF-8</p>
 * <p>转换对象为XML时，必须使用JAXB注解对类和属性进行标注</p>
 * <p>转换对象中的指定属性值为JSON/YAML时，必须使用Jackson注解对属性进行标注</p>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Jan 6, 2021 17:10:23 $
 */
@XmlTransient
@XmlAccessorType(XmlAccessType.NONE)
@OutputConfig(type = StringUtils.StringType.XML, formatted = true)
public abstract class BeanObject implements Serializable, Cloneable {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 6900853002518080456L;

	/**
	 * <h3 class="en-US">Convert the current object to not formatted JSON string</h3>
	 * <h3 class="zh-CN">转换当前实例对象为未经格式化的JSON字符串</h3>
	 *
	 * @return <span class="en-US">Converted JSON string</span>
	 * <span class="zh-CN">转换后的JSON字符串</span>
	 */
	public final String toJson() {
		return StringUtils.objectToString(this, StringUtils.StringType.JSON, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Convert the current object to formatted JSON string</h3>
	 * <h3 class="zh-CN">转换当前实例对象为格式化的JSON字符串</h3>
	 *
	 * @return <span class="en-US">Converted JSON string</span>
	 * <span class="zh-CN">转换后的JSON字符串</span>
	 */
	public final String toFormattedJson() {
		return StringUtils.objectToString(this, StringUtils.StringType.JSON, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Convert the current object to not formatted YAML string</h3>
	 * <h3 class="zh-CN">转换当前实例对象为未经格式化的YAML字符串</h3>
	 *
	 * @return <span class="en-US">Converted YAML string</span>
	 * <span class="zh-CN">转换后的YAML字符串</span>
	 */
	public final String toYaml() {
		return StringUtils.objectToString(this, StringUtils.StringType.YAML, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Convert the current object to formatted YAML string</h3>
	 * <h3 class="zh-CN">转换当前实例对象为格式化的YAML字符串</h3>
	 *
	 * @return <span class="en-US">Converted JSON string</span>
	 * <span class="zh-CN">转换后的JSON字符串</span>
	 */
	public final String toFormattedYaml() {
		return StringUtils.objectToString(this, StringUtils.StringType.YAML, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">Convert the current object to not formatted XML string</h3>
	 * <h3 class="zh-CN">转换当前实例对象为未经格式化的XML字符串</h3>
	 *
	 * @return <span class="en-US">Converted XML string, or empty string "" if an error occurs</span>
	 * <span class="zh-CN">转换后的XML字符串，如果转换过程中出现异常则返回空字符串</span>
	 */
	public final String toXML() {
		return this.toXML(Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Convert the current object to XML string</h3>
	 * <h3 class="zh-CN">转换当前实例对象为XML字符串</h3>
	 *
	 * @param formattedOutput <span class="en-US">Output formatted XML string status. <code>TRUE</code> or <code>FALSE</code></span>
	 *                        <span class="zh-CN">输出格式化的XML字符串状态。<code>TRUE</code>或<code>FALSE</code></span>
	 * @return <span class="en-US">Converted XML string, or empty string "" if an error occurs</span>
	 * <span class="zh-CN">转换后的XML字符串，如果转换过程中出现异常则返回空字符串</span>
	 */
	public final String toXML(final boolean formattedOutput) {
		return this.toXML(Boolean.TRUE, formattedOutput);
	}

	/**
	 * <h3 class="en-US">Convert the current object to XML string</h3>
	 * <h3 class="zh-CN">转换当前实例对象为XML字符串</h3>
	 *
	 * @param formattedOutput <span class="en-US">Output formatted XML string status. <code>TRUE</code> or <code>FALSE</code></span>
	 *                        <span class="zh-CN">输出格式化的XML字符串状态。<code>TRUE</code>或<code>FALSE</code></span>
	 * @param encoding        <span class="en-US">Output string encoding</span>
	 *                        <span class="zh-CN">输出字符串使用的字符集</span>
	 * @return <span class="en-US">Converted XML string, or empty string "" if an error occurs</span>
	 * <span class="zh-CN">转换后的XML字符串，如果转换过程中出现异常则返回空字符串</span>
	 */
	public final String toXML(final boolean formattedOutput, final String encoding) {
		return this.toXML(Boolean.TRUE, formattedOutput, encoding);
	}

	/**
	 * <h3 class="en-US">Convert the current object to XML string</h3>
	 * <h3 class="zh-CN">转换当前实例对象为XML字符串</h3>
	 *
	 * @param outputFragment  <span class="en-US">Output XML fragment status. <code>TRUE</code> or <code>FALSE</code></span>
	 *                        <span class="zh-CN">输出的XML声明字符串状态。<code>TRUE</code>或<code>FALSE</code></span>
	 * @param formattedOutput <span class="en-US">Output formatted XML string status. <code>TRUE</code> or <code>FALSE</code></span>
	 *                        <span class="zh-CN">输出格式化的XML字符串状态。<code>TRUE</code>或<code>FALSE</code></span>
	 * @return <span class="en-US">Converted XML string, or empty string "" if an error occurs</span>
	 * <span class="zh-CN">转换后的XML字符串，如果转换过程中出现异常则返回空字符串</span>
	 */
	public final String toXML(final boolean outputFragment, final boolean formattedOutput) {
		return this.toXML(outputFragment, formattedOutput, Globals.DEFAULT_ENCODING);
	}

	/**
	 * <h3 class="en-US">Convert the current object to XML string</h3>
	 * <h3 class="zh-CN">转换当前实例对象为XML字符串</h3>
	 *
	 * @param outputFragment  <span class="en-US">Output XML fragment status. <code>TRUE</code> or <code>FALSE</code></span>
	 *                        <span class="zh-CN">输出的XML声明字符串状态。<code>TRUE</code>或<code>FALSE</code></span>
	 * @param formattedOutput <span class="en-US">Output formatted XML string status. <code>TRUE</code> or <code>FALSE</code></span>
	 *                        <span class="zh-CN">输出格式化的XML字符串状态。<code>TRUE</code>或<code>FALSE</code></span>
	 * @param encoding        <span class="en-US">Output string encoding</span>
	 *                        <span class="zh-CN">输出字符串使用的字符集</span>
	 * @return <span class="en-US">Converted XML string, or empty string "" if an error occurs</span>
	 * <span class="zh-CN">转换后的XML字符串，如果转换过程中出现异常则返回空字符串</span>
	 */
	public final String toXML(final boolean outputFragment, final boolean formattedOutput, final String encoding) {
		return StringUtils.objectToString(this, StringUtils.StringType.XML, formattedOutput, outputFragment, encoding);
	}

	/**
	 * (non-javadoc)
	 *
	 * @see Object#equals(Object)
	 */
	@Override
	public final boolean equals(final Object o) {
		if (o == null || !o.getClass().equals(this.getClass())) {
			return Boolean.FALSE;
		}
		if (this == o) {
			return Boolean.TRUE;
		}
		return Arrays.stream(this.getClass().getDeclaredFields())
				.filter(field -> !ReflectionUtils.staticMember(field))
				.allMatch(field ->
						Objects.equals(ReflectionUtils.getFieldValue(field, this),
								ReflectionUtils.getFieldValue(field, o)));
	}

	/**
	 * (non-javadoc)
	 *
	 * @see Object#hashCode()
	 */
	@Override
	public final int hashCode() {
		int result = Globals.INITIALIZE_INT_VALUE;
		try {
			for (Field field : this.getClass().getDeclaredFields()) {
				Object origValue = ReflectionUtils.getFieldValue(field, this);
				result = Globals.MULTIPLIER * result + (origValue != null ? origValue.hashCode() : 0);
			}
		} catch (Exception e) {
			result = Globals.DEFAULT_VALUE_INT;
		}
		return result;
	}

	/**
	 * (non-javadoc)
	 *
	 * @see Object#toString()
	 */
	@Override
	public final String toString() {
		return Optional.ofNullable(this.getClass().getAnnotation(OutputConfig.class))
				.map(outputConfig -> this.toString(outputConfig.type(), outputConfig.formatted()))
				.orElse(this.toString(StringUtils.StringType.SIMPLE, Boolean.FALSE));
	}

	public final String toString(final StringUtils.StringType stringType, final boolean formatOutput) {
		switch (stringType) {
			case XML:
				return this.toXML(formatOutput);
			case JSON:
				return formatOutput ? this.toFormattedJson() : this.toJson();
			case YAML:
				return formatOutput ? this.toFormattedYaml() : this.toYaml();
			case SERIALIZABLE:
				return StringUtils.objectToString(this, StringUtils.StringType.SERIALIZABLE, formatOutput);
			default:
				return super.toString();
		}
	}

	/**
	 * <h3 class="en-US">Clone current object</h3>
	 * <h3 class="zh-CN">复制当前对象</h3>
	 *
	 * @param deepClone <span class="en-US">Deep clone flag</span>
	 *                  <span class="zh-CN">深克隆标记</span>
	 * @return <span class="en-US">Clone object</span>
	 * <span class="zh-CN">克隆的对象</span>
	 */
	public final Object clone(final boolean deepClone) {
		if (deepClone) {
			return ConvertUtils.toObject(ConvertUtils.toByteArray(this));
		} else {
			try {
				return super.clone();
			} catch (CloneNotSupportedException e) {
				throw new AssertionError("Clone object failed! ", e);
			}
		}
	}
}
