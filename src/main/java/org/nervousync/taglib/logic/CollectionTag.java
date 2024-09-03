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

package org.nervousync.taglib.logic;

import jakarta.servlet.jsp.JspException;
import jakarta.servlet.jsp.PageContext;
import jakarta.servlet.jsp.tagext.JspFragment;
import jakarta.servlet.jsp.tagext.SimpleTagSupport;
import org.nervousync.commons.Globals;
import org.nervousync.utils.CollectionUtils;
import org.nervousync.utils.StringUtils;
import org.nervousync.utils.TagUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * <h2 class="en-US">Abstract class for traversing data labels</h2>
 * <h2 class="zh-CN">用于遍历数据标签的抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 26, 2023 19:02:27 $
 */
public abstract class CollectionTag extends SimpleTagSupport {

	/**
	 * <span class="en-US">Data to traverse</span>
	 * <span class="zh-CN">要遍历的数据</span>
	 */
	private Object items = null;
	/**
	 * <span class="en-US">The variable name of the data when traversing</span>
	 * <span class="zh-CN">遍历时数据的变量名</span>
	 */
	private String var = null;
	/**
	 * <span class="en-US">Valid range of data variables</span>
	 * <span class="zh-CN">数据变量的生效范围</span>
	 */
	private String scope = "page";
	/**
	 * <span class="en-US">The variable name of the data variable index</span>
	 * <span class="zh-CN">数据变量索引的变量名</span>
	 */
	private String statusVar = null;
	/**
	 * <span class="en-US">Valid range of data variable index</span>
	 * <span class="zh-CN">数据变量索引的生效范围</span>
	 */
	private String statusScope = "page";

	/**
	 * @return the items
	 */
	public Object getItems() {
		return items;
	}

	/**
	 * @param items the items to set
	 */
	public void setItems(Object items) {
		this.items = items;
	}

	/**
	 * @return the var
	 */
	public String getVar() {
		return var;
	}

	/**
	 * @param var the var to set
	 */
	public void setVar(String var) {
		this.var = var;
	}

	/**
	 * @return the scope
	 */
	public String getScope() {
		return scope;
	}

	/**
	 * @param scope the scope to set
	 */
	public void setScope(String scope) {
		this.scope = scope;
	}

	/**
	 * @return the statusVar
	 */
	public String getStatusVar() {
		return statusVar;
	}

	/**
	 * @param statusVar the statusVar to set
	 */
	public void setStatusVar(String statusVar) {
		this.statusVar = statusVar;
	}

	/**
	 * @return the statusScope
	 */
	public String getStatusScope() {
		return statusScope;
	}

	/**
	 * @param statusScope the statusScope to set
	 */
	public void setStatusScope(String statusScope) {
		this.statusScope = statusScope;
	}

	@Override
	public final void doTag() throws JspException, IOException {
		// initialize status variable
		Status status = new Status(this.startIndex(), this.endIndex(), this.step());

		if (status.getStep() <= 0) {
			return;
		}

		// convert the specified collection to list
		List<Object> itemsList = new ArrayList<>();
		List<Integer> indexList = new ArrayList<>();

		if (this.items == null) {
			int endIndex = (status.getEnd() == Globals.DEFAULT_VALUE_INT)
					? Globals.INITIALIZE_INT_VALUE : status.getEnd();
			for (int i = status.getStart(); i < endIndex; i += status.getStep()) {
				itemsList.add(i + 1);
				indexList.add(i);
			}
		} else {
			List<?> itemList = CollectionUtils.toList(this.items);
			int endIndex = (status.getEnd() == Globals.DEFAULT_VALUE_INT) ? itemList.size() : status.getEnd();
			for (int i = status.getStart(); i <= endIndex; i += status.getStep()) {
				itemsList.add(itemList.get(i));
				indexList.add(i);
			}
		}

		// obtain JSP body
		JspFragment body = this.getJspBody();
		if (body == null) {
			return;
		}

		PageContext pageContext = (PageContext) this.getJspContext();

		for (int i = 0; i < itemsList.size(); i++) {
			Object currentObject = itemsList.get(i);

			// set current object
			status.setCurrentObject(currentObject);

			// set index
			status.setIndex(indexList.get(i));

			if (StringUtils.notBlank(this.var)) {
				pageContext.setAttribute(this.var, currentObject, TagUtils.getScope(this.scope));
			}

			// expose status to the specified scope
			if (StringUtils.notBlank(this.statusVar)) {
				pageContext.setAttribute(this.statusVar, status, TagUtils.getScope(this.statusScope));
			}

			// invoke body content
			body.invoke(null);
		}
	}

	protected abstract int startIndex();

	protected abstract int endIndex();

	protected abstract int step();

	private static final class Status {

		private final Integer start;

		private final Integer end;

		private final Integer step;

		private int index;

		private int count;

		private Object currentObject;

		private Status(final Integer start, final Integer end, final Integer step) {
			this.start = (start != null) ? start : Globals.INITIALIZE_INT_VALUE;
			this.end = (end != null) ? end : Globals.INITIALIZE_INT_VALUE;
			this.step = (step != null) ? step : 1;
		}

		/**
		 * @return the start
		 */
		public Integer getStart() {
			return start;
		}

		/**
		 * @return the end
		 */
		public Integer getEnd() {
			return end;
		}

		/**
		 * @return the step
		 */
		public Integer getStep() {
			return step;
		}

		/**
		 * @return the index
		 */
		public int getIndex() {
			return index;
		}

		/**
		 * @param index the index to set
		 */
		public void setIndex(int index) {
			this.index = index;
		}

		/**
		 * @return the count
		 */
		public int getCount() {
			return count;
		}

		public void setCount(int count) {
			this.count = count;
		}

		/**
		 * @return the currentObject
		 */
		public Object getCurrentObject() {
			return currentObject;
		}

		/**
		 * @param currentObject the currentObject to set
		 */
		public void setCurrentObject(Object currentObject) {
			this.currentObject = currentObject;
		}
	}
}
