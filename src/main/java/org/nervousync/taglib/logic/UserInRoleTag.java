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

import jakarta.annotation.Nonnull;
import jakarta.servlet.http.HttpServletRequest;
import org.nervousync.commons.Globals;
import org.nervousync.utils.StringUtils;

import java.util.*;

public final class UserInRoleTag extends ConditionTag {

	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = -2840483413273797343L;

	private String roles = null;

	@Override
	protected boolean condition() {
		if (StringUtils.isEmpty(roles)) {
			return Boolean.FALSE;
		}
		HttpServletRequest httpRequest = (HttpServletRequest) this.pageContext.getRequest();
		Map<Integer, Boolean> resultMap = new HashMap<>();
		List<String> roleList = this.split();
		for (int i = Globals.INITIALIZE_INT_VALUE; i < roleList.size() - 1; i++) {
			resultMap.put(i, this.checkRoles(httpRequest, roleList.get(i), resultMap));
		}
		return this.checkRoles(httpRequest, roleList.get(roleList.size() - 1), resultMap);
	}

	public String getRoles() {
		return roles;
	}

	public void setRoles(String roles) {
		this.roles = roles;
	}

	private boolean checkRoles(@Nonnull final HttpServletRequest httpRequest, @Nonnull final String roleCode,
	                           @Nonnull final Map<Integer, Boolean> resultMap) {
		if (StringUtils.containsIgnoreCase(roleCode, "|")) {
			return Optional.of(StringUtils.tokenizeToStringArray(roleCode, "|"))
					.filter(itemCodes -> itemCodes.length > 0)
					.map(itemCodes ->
							Arrays.stream(itemCodes).anyMatch(itemCode ->
									this.checkRoles(httpRequest, itemCode, resultMap)))
					.orElse(Boolean.FALSE);
		} else if (StringUtils.containsIgnoreCase(roleCode, "&")) {
			return Optional.of(StringUtils.tokenizeToStringArray(roleCode, "&"))
					.filter(itemCodes -> itemCodes.length > 0)
					.map(itemCodes ->
							Arrays.stream(itemCodes).allMatch(itemCode ->
									this.checkRoles(httpRequest, itemCode, resultMap)))
					.orElse(Boolean.FALSE);
		} else {
			return this.checkRole(httpRequest, roleCode, resultMap);
		}
	}

	private boolean checkRole(@Nonnull final HttpServletRequest httpRequest, @Nonnull final String roleCode,
	                          @Nonnull final Map<Integer, Boolean> resultMap) {
		if (roleCode.startsWith("{") && roleCode.endsWith("}")) {
			return resultMap.get(Integer.valueOf(roleCode.substring(1, roleCode.length() - 1)));
		} else if (StringUtils.containsIgnoreCase(roleCode, "|")
				|| StringUtils.containsIgnoreCase(roleCode, "&")) {
			return checkRoles(httpRequest, roleCode, resultMap);
		} else {
			return httpRequest.isUserInRole(roleCode);
		}
	}

	private List<String> split() {
		List<Integer> beginIndexList = new ArrayList<>();
		List<Integer> endIndexList = new ArrayList<>();
		int index = Globals.INITIALIZE_INT_VALUE;
		while (index < this.roles.length()) {
			switch (this.roles.charAt(index)) {
				case '(':
					beginIndexList.add(index);
					break;
				case ')':
					endIndexList.add(index + 1);
					break;
			}
			index++;
		}

		beginIndexList.sort((o1, o2) -> Integer.compare(o2, o1));
		List<String> codeList = new ArrayList<>();
		beginIndexList.forEach(beginIndex -> {
			Integer endIndex = endIndexList.stream()
					.filter(idx -> beginIndex < idx)
					.min(Integer::compareTo)
					.orElse(Globals.DEFAULT_VALUE_INT);
			if (endIndex != Globals.DEFAULT_VALUE_INT) {
				codeList.add(this.roles.substring(beginIndex, endIndex));
				endIndexList.remove(endIndex);
			}
		});
		if (!this.roles.startsWith("(")) {
			codeList.add("(" + this.roles + ")");
		}
		List<String> roleList = new ArrayList<>();
		for (int i = codeList.size() - 1; i >= Globals.INITIALIZE_INT_VALUE; i--) {
			String roleCode = codeList.get(i);
			for (int j = i - 1; j >= Globals.INITIALIZE_INT_VALUE; j--) {
				roleCode = StringUtils.replace(roleCode, codeList.get(j), "{" + j + "}");
			}
			roleList.add(roleCode);
		}
		Collections.reverse(roleList);
		roleList.replaceAll(code -> code.substring(1, code.length() - 1));

		return roleList;
	}
}
