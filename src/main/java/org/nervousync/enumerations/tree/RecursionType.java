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

package org.nervousync.enumerations.tree;

/**
 * <h2 class="en-US">Recursive type enumeration value</h2>
 * <h2 class="zh-CN">递归类型枚举值</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Nov 3, 2017 17:22:19 $
 */
public enum RecursionType {
    /**
	 * <span class="en-US">Normal</span>
	 * <span class="zh-CN">默认</span>
     */
    Normal,
    /**
	 * <span class="en-US">Depth first</span>
	 * <span class="zh-CN">深度优先</span>
     */
    Depth,
    /**
	 * <span class="en-US">Breadth first</span>
	 * <span class="zh-CN">广度优先</span>
     */
    Breadth
}
