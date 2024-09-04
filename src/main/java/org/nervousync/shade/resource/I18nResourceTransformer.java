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

package org.nervousync.shade.resource;

import jakarta.annotation.Nonnull;
import org.apache.maven.plugins.shade.relocation.Relocator;
import org.apache.maven.plugins.shade.resource.ReproducibleResourceTransformer;
import org.nervousync.beans.i18n.BundleError;
import org.nervousync.beans.i18n.BundleLanguage;
import org.nervousync.beans.i18n.BundleMessage;
import org.nervousync.beans.i18n.BundleResource;
import org.nervousync.commons.Globals;
import org.nervousync.utils.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/**
 * <h2 class="en-US">Transformer implement class which using for merge internationalization resource file</h2>
 * <h2 class="zh-CN">用于合并国际化资源文件的传送器实现</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Oct 21, 2023 09:05:28 $
 */
public final class I18nResourceTransformer implements ReproducibleResourceTransformer {
	private final BundleResource bundleResource = new BundleResource();

	private void mergeErrors(@Nonnull final List<BundleError> existsErrors, final List<BundleError> mergeErrors) {
		if (mergeErrors == null || mergeErrors.isEmpty()) {
			return;
		}
		if (existsErrors.isEmpty()) {
			existsErrors.addAll(mergeErrors);
			return;
		}

		mergeErrors.forEach(bundleError -> {
			if (existsErrors.stream().noneMatch(existError ->
					ObjectUtils.nullSafeEquals(existError.getErrorCode(), bundleError.getErrorCode()))) {
				existsErrors.add(bundleError);
			} else {
				existsErrors.replaceAll(existError -> {
					if (ObjectUtils.nullSafeEquals(existError.getErrorCode(), bundleError.getErrorCode())) {
						return bundleError;
					}
					return existError;
				});
			}
		});
	}

	private void mergeLanguage(@Nonnull final List<BundleLanguage> existLanguages,
	                           final List<BundleLanguage> mergeLanguages) {
		if (mergeLanguages == null || mergeLanguages.isEmpty()) {
			return;
		}

		if (existLanguages.isEmpty()) {
			existLanguages.addAll(mergeLanguages);
			return;
		}

		mergeLanguages.forEach(bundleLanguage -> {
			if (existLanguages.stream().noneMatch(existLanguage ->
					ObjectUtils.nullSafeEquals(existLanguage.getLanguageCode(), bundleLanguage.getLanguageCode()))) {
				existLanguages.add(bundleLanguage);
			} else {
				existLanguages.replaceAll(existLanguage -> {
					if (ObjectUtils.nullSafeEquals(existLanguage.getLanguageCode(), bundleLanguage.getLanguageCode())) {
						List<BundleMessage> existsMessages = existLanguage.getBundleMessages();
						this.mergeMessage(existsMessages, bundleLanguage.getBundleMessages());
						existLanguage.setBundleMessages(existsMessages);
					}
					return existLanguage;
				});
			}
		});
	}

	private void mergeMessage(@Nonnull final List<BundleMessage> existsMessages,
	                          final List<BundleMessage> mergeMessages) {
		if (mergeMessages == null || mergeMessages.isEmpty()) {
			return;
		}
		if (existsMessages.isEmpty()) {
			existsMessages.addAll(mergeMessages);
			return;
		}

		mergeMessages.forEach(bundleMessage -> {
			if (existsMessages.stream().noneMatch(existMessage ->
					ObjectUtils.nullSafeEquals(existMessage.getMessageKey(), bundleMessage.getMessageKey()))) {
				existsMessages.add(bundleMessage);
			} else {
				existsMessages.replaceAll(existMessage -> {
					if (ObjectUtils.nullSafeEquals(existMessage.getMessageKey(), bundleMessage.getMessageKey())) {
						return bundleMessage;
					}
					return existMessage;
				});
			}
		});
	}

	@Override
	public void processResource(final String resource, final InputStream inputStream,
	                            final List<Relocator> relocatorList) throws IOException {
		this.processResource(resource, inputStream, relocatorList, 0L);
	}

	@Override
	public void processResource(final String resource, final InputStream inputStream,
	                            final List<Relocator> relocatorList, final long time) throws IOException {
		if (StringUtils.isEmpty(resource)) {
			return;
		}
		if (ObjectUtils.nullSafeEquals(resource, MultilingualUtils.BUNDLE_RESOURCE_PATH)) {
			Optional.ofNullable(StringUtils.streamToObject(inputStream, StringUtils.StringType.JSON, BundleResource.class))
					.filter(readResource ->
							ObjectUtils.nullSafeEquals(readResource.getGroupId(), this.bundleResource.getGroupId())
									&& ObjectUtils.nullSafeEquals(readResource.getBundle(), this.bundleResource.getBundle()))
					.ifPresent(readResource -> {
						List<BundleError> bundleErrors = this.bundleResource.getBundleErrors();
						this.mergeErrors(bundleErrors, readResource.getBundleErrors());
						this.bundleResource.setBundleErrors(bundleErrors);

						List<BundleLanguage> bundleLanguages = this.bundleResource.getBundleLanguages();
						this.mergeLanguage(bundleLanguages, readResource.getBundleLanguages());
						this.bundleResource.setBundleLanguages(bundleLanguages);
					});
		}
	}

	@Override
	public boolean canTransformResource(final String resource) {
		return ObjectUtils.nullSafeEquals(resource, MultilingualUtils.BUNDLE_RESOURCE_PATH);
	}

	@Override
	public boolean hasTransformedResource() {
		return Boolean.TRUE;
	}

	@Override
	public void modifyOutputStream(final JarOutputStream jarOutputStream) throws IOException {
		long currentTime = DateTimeUtils.currentTimeMillis() / 1000 * 1000;
		JarEntry jarEntry = new JarEntry(MultilingualUtils.BUNDLE_RESOURCE_PATH);
		jarEntry.setTime(currentTime);
		jarOutputStream.putNextEntry(jarEntry);
		IOUtils.writeContent(this.bundleResource.toString(), FileUtils.CRLF, jarOutputStream, Globals.DEFAULT_ENCODING);
	}

	public void setGroupId(String groupId) {
		this.bundleResource.setGroupId(groupId);
	}

	public void setBundle(String bundle) {
		this.bundleResource.setBundle(bundle);
	}
}
