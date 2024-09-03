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
package org.nervousync.beans.image;

import org.nervousync.commons.Globals;

/**
 * <h2 class="en-US">Cut options of image cut operate</h2>
 * <h2 class="zh-CN">用于图片剪切操作的剪切选项</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.0 $ $Date: Sep 22, 2022 17:36:55 $
 */
public final class CutOptions {
	/**
	 * <h3 class="en-US">Begin position X, default value is 0</h3>
	 * <h3 class="zh-CN">起始X坐标值，默认为0</h3>
	 */
	private final int positionX;
	/**
	 * <h3 class="en-US">Begin position Y, default value is 0</h3>
	 * <h3 class="zh-CN">起始Y坐标值，默认为0</h3>
	 */
	private final int positionY;
	/**
	 * <h3 class="en-US">Cut width value</h3>
	 * <h3 class="zh-CN">剪切后的宽度</h3>
	 */
	private final int cutWidth;
	/**
	 * <h3 class="en-US">Cut height value</h3>
	 * <h3 class="zh-CN">剪切后的高度</h3>
	 */
	private final int cutHeight;

	/**
	 * <h3 class="en-US">Constructor for CutOptions</h3>
	 * <h3 class="zh-CN">CutOptions的构造方法</h3>
	 *
	 * @param positionX <span class="en-US">Begin position X, default value is 0</span>
	 *                  <span class="zh-CN">起始X坐标值，默认为0</span>
	 * @param positionY <span class="en-US">Begin position Y, default value is 0</span>
	 *                  *                  <span class="zh-CN">起始Y坐标值，默认为0</span>
	 * @param cutWidth  <span class="en-US">Cut width value</span>
	 *                  <span class="zh-CN">剪切后的宽度</span>
	 * @param cutHeight <span class="en-US">Cut height value</span>
	 *                  <span class="zh-CN">剪切后的高度</span>
	 */
	private CutOptions(final int positionX, final int positionY, final int cutWidth, final int cutHeight) {
		this.positionX = positionX < 0 ? Globals.INITIALIZE_INT_VALUE : positionX;
		this.positionY = positionY < 0 ? Globals.INITIALIZE_INT_VALUE : positionY;
		this.cutWidth = cutWidth;
		this.cutHeight = cutHeight;
	}

	/**
	 * <h3 class="en-US">Static method for initialize CutOptions from default position (0, 0)</h3>
	 * <h3 class="zh-CN">用于初始化CutOptions的静态方法，使用默认起始坐标（0，0）</h3>
	 *
	 * @param cutWidth  <span class="en-US">Cut width value</span>
	 *                  <span class="zh-CN">剪切后的宽度</span>
	 * @param cutHeight <span class="en-US">Cut height value</span>
	 *                  <span class="zh-CN">剪切后的高度</span>
	 * @return <span class="en-US">Initialized CutOptions instance</span>
	 * <span class="en-US">初始化的CutOptions实例对象</span>
	 */
	public static CutOptions newInstance(final int cutWidth, final int cutHeight) {
		return newInstance(Globals.DEFAULT_VALUE_INT, Globals.DEFAULT_VALUE_INT, cutWidth, cutHeight);
	}

	/**
	 * <h3 class="en-US">Static method for initialize CutOptions by given begin position (positionX, positionY)</h3>
	 * <h3 class="zh-CN">用于初始化CutOptions的静态方法，使用给定的起始坐标（positionX，positionY）</h3>
	 *
	 * @param positionX <span class="en-US">Begin position X, default value is 0</span>
	 *                  <span class="zh-CN">起始X坐标值，默认为0</span>
	 * @param positionY <span class="en-US">Begin position Y, default value is 0</span>
	 *                  <span class="zh-CN">起始Y坐标值，默认为0</span>
	 * @param cutWidth  <span class="en-US">Cut width value</span>
	 *                  <span class="zh-CN">剪切后的宽度</span>
	 * @param cutHeight <span class="en-US">Cut height value</span>
	 *                  <span class="zh-CN">剪切后的高度</span>
	 * @return <span class="en-US">Initialized CutOptions instance</span>
	 * <span class="en-US">初始化的CutOptions实例对象</span>
	 */
	public static CutOptions newInstance(final int positionX, final int positionY,
	                                     final int cutWidth, final int cutHeight) {
		return new CutOptions(positionX, positionY, cutWidth, cutHeight);
	}

	/**
	 * <h3 class="en-US">Getter method for position X</h3>
	 * <h3 class="zh-CN">起始X坐标的Getter方法</h3>
	 *
	 * @return <span class="en-US">Value of begin position X</span>
	 * <span class="zh-CN">起始X坐标值</span>
	 */
	public int getPositionX() {
		return positionX;
	}

	/**
	 * <h3 class="en-US">Getter method for position Y</h3>
	 * <h3 class="zh-CN">起始Y坐标的Getter方法</h3>
	 *
	 * @return <span class="en-US">Value of begin position Y</span>
	 * <span class="zh-CN">起始Y坐标值</span>
	 */
	public int getPositionY() {
		return positionY;
	}

	/**
	 * <h3 class="en-US">Getter method for cut width</h3>
	 * <h3 class="zh-CN">剪切宽度的Getter方法</h3>
	 *
	 * @return <span class="en-US">Value of cut width</span>
	 * <span class="zh-CN">剪切宽度值</span>
	 */
	public int getCutWidth() {
		return cutWidth;
	}

	/**
	 * <h3 class="en-US">Getter method for cut height</h3>
	 * <h3 class="zh-CN">剪切高度的Getter方法</h3>
	 *
	 * @return <span class="en-US">Value of cut height</span>
	 * <span class="zh-CN">剪切高度值</span>
	 */
	public int getCutHeight() {
		return cutHeight;
	}
}
