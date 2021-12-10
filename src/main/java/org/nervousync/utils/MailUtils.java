/*
 * Licensed to the Nervousync Studio (NSYC) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
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
package org.nervousync.utils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.*;

import com.sun.mail.imap.IMAPFolder;
import com.sun.mail.imap.IMAPMessage;
import com.sun.mail.pop3.POP3Folder;
import jakarta.activation.DataHandler;
import jakarta.activation.DataSource;
import jakarta.activation.FileDataSource;
import jakarta.mail.*;
import jakarta.mail.internet.*;
import jakarta.mail.util.ByteArrayDataSource;
import org.nervousync.exceptions.builder.BuilderException;
import org.nervousync.mail.MailObject;
import org.nervousync.mail.authenticator.DefaultAuthenticator;
import org.nervousync.mail.config.MailConfig;
import org.nervousync.mail.operator.ReceiveOperator;
import org.nervousync.mail.operator.SendOperator;
import org.nervousync.mail.config.ServerConfig;
import org.nervousync.mail.protocol.impl.IMAPProtocol;
import org.nervousync.mail.protocol.impl.POP3Protocol;
import org.nervousync.mail.protocol.impl.SMTPProtocol;
import org.nervousync.commons.core.Globals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The type Mail utils.
 *
 * @author Steven Wee     <a href="mailto:wmkm0113@Hotmail.com">wmkm0113@Hotmail.com</a>
 * @version $Revision: 1.0 $ $Date: Jul 31, 2012 8:54:04 PM $
 */
public final class MailUtils {

	private MailUtils() {
	}

	/**
	 * Initialize a new mail agent by given mail config
	 *
	 * @param mailConfig 		Mail config
	 * @return Optional instance of generated mail agent or empty Option instance if mail config is invalid
	 */
	public static Optional<Agent> mailAgent(MailConfig mailConfig) {
		if (mailConfig == null || StringUtils.isEmpty(mailConfig.getUserName())
				|| StringUtils.isEmpty(mailConfig.getPassWord())) {
			return Optional.empty();
		}
		return Optional.of(new Agent(mailConfig));
	}

	/**
	 * Generate mail server config builder instance by given server config
	 *
	 * @param serverConfig		Server config
	 * @return	Mail server config builder instance
	 * @throws BuilderException	Builder Exception
	 */
	public static ServerConfig.Builder builder(ServerConfig serverConfig) throws BuilderException {
		return new ServerConfig.Builder(serverConfig);
	}

	/**
	 * Generate a new SMTP server config builder
	 *
	 * @return	Generated config builder
	 * @throws BuilderException	Builder Exception
	 */
	public static ServerConfig.Builder SMTPBuilder() throws BuilderException {
		return new ServerConfig.Builder("SMTP");
	}

	/**
	 * Generate a new POP3 server config builder
	 *
	 * @return	Generated config builder
	 * @throws BuilderException	Builder Exception
	 */
	public static ServerConfig.Builder POP3Builder() throws BuilderException {
		return new ServerConfig.Builder("POP3");
	}

	/**
	 * Generate a new IMAP server config builder
	 *
	 * @return	Generated config builder
	 * @throws BuilderException	Builder Exception
	 */
	public static ServerConfig.Builder IMAPBuilder() throws BuilderException {
		return new ServerConfig.Builder("IMAP");
	}

	public static final class Agent {

		private final Logger logger = LoggerFactory.getLogger(this.getClass());

		private final String userName;
		private final String passWord;
		private final ServerConfig sendConfig;
		private final SendOperator sendOperator;
		private final ServerConfig receiveConfig;
		private final ReceiveOperator receiveOperator;
		private final String storagePath;

		private Agent(MailConfig mailConfig) {
			this.userName = mailConfig.getUserName().toLowerCase();
			this.passWord = mailConfig.getPassWord();
			if (mailConfig.getSendConfig() == null
					|| !"SMTP".equalsIgnoreCase(mailConfig.getSendConfig().getProtocolOption())) {
				this.sendConfig = null;
				this.sendOperator = null;
			} else {
				this.sendConfig = mailConfig.getSendConfig();
				this.sendOperator = new SMTPProtocol();
			}
			if (mailConfig.getReceiveConfig() == null
					|| StringUtils.isEmpty(mailConfig.getReceiveConfig().getProtocolOption())) {
				this.receiveConfig = null;
				this.receiveOperator = null;
			} else {
				this.receiveConfig = mailConfig.getReceiveConfig();
				switch (this.receiveConfig.getProtocolOption().toUpperCase()) {
					case "IMAP":
						this.receiveOperator = new IMAPProtocol();
						break;
					case "POP3":
						this.receiveOperator = new POP3Protocol();
						break;
					default:
						this.receiveOperator = null;
						break;
				}
			}
			this.storagePath = mailConfig.getStoragePath();
		}

		public boolean sendMail(MailObject mailObject) {
			if (this.sendOperator == null) {
				//	Not config send server
				return Boolean.FALSE;
			}
			try {
				Properties properties = this.sendOperator.readConfig(this.sendConfig);
				if (StringUtils.notBlank(this.userName)) {
					properties.setProperty("mail.smtp.from", this.userName);
				}
				Session session =
						Session.getInstance(properties, new DefaultAuthenticator(this.userName, this.passWord));
				session.setDebug(this.logger.isDebugEnabled());
				if (StringUtils.isEmpty(mailObject.getSendAddress())) {
					mailObject.setSendAddress(this.userName);
				}
				Transport.send(convert(session, mailObject));
				return Boolean.TRUE;
			} catch (MessagingException e) {
				this.logger.error("Send mail failed!");
				if (this.logger.isDebugEnabled()) {
					this.logger.debug("Stack message: ", e);
				}
				return Boolean.FALSE;
			}
		}

		/**
		 * Mail count int.
		 *
		 * @return the int
		 */
		public int mailCount() {
			return this.mailCount(Globals.DEFAULT_EMAIL_FOLDER_INBOX);
		}

		/**
		 * Mail count int.
		 *
		 * @param folderName the folder name
		 * @return the int
		 */
		public int mailCount(String folderName) {
			if (this.receiveOperator == null) {
				//	Not config receive server
				return Globals.DEFAULT_VALUE_INT;
			}
			try (Store store = connect(); Folder folder = openReadOnlyFolder(store, folderName)) {
				if (folder.exists() && folder.isOpen()) {
					return folder.getMessageCount();
				}
			} catch (Exception e) {
				if (this.logger.isDebugEnabled()) {
					this.logger.debug("Receive Message Error! ", e);
				}
			}
			return Globals.DEFAULT_VALUE_INT;
		}

		/**
		 * Mail list list.
		 *
		 * @return the list
		 */
		public List<String> mailList() {
			return this.mailList(Globals.DEFAULT_EMAIL_FOLDER_INBOX);
		}

		/**
		 * Mail list list.
		 *
		 * @param folderName the folder name
		 * @return the list
		 */
		public List<String> mailList(String folderName) {
			return mailList(folderName, Globals.DEFAULT_VALUE_INT, Globals.DEFAULT_VALUE_INT);
		}

		/**
		 * Mail list list.
		 *
		 * @param folderName the folder name
		 * @param begin      the begin
		 * @param end        the end
		 * @return the list
		 */
		public List<String> mailList(String folderName, int begin, int end) {
			if (this.receiveOperator == null || end < begin) {
				return Collections.emptyList();
			}

			try (Store store = connect(); Folder folder = openReadOnlyFolder(store, folderName)) {
				if (!folder.exists() || !folder.isOpen()) {
					return Collections.emptyList();
				}

				if (begin < 1) {
					begin = 1;
				}
				if (end < 0) {
					end = folder.getMessageCount();
				}

				List<String> mailList = new ArrayList<>();
				for (Message message : folder.getMessages(begin, end)) {
					mailList.add(this.receiveOperator.readUID(folder, message));
				}
				return mailList;
			} catch (Exception e) {
				if (this.logger.isDebugEnabled()) {
					this.logger.debug("Receive Message Error! ", e);
				}
			}
			return Collections.emptyList();
		}

		/**
		 * Read mail optional.
		 *
		 * @param folderName the folder name
		 * @param uid        the uid
		 * @return the optional
		 */
		public Optional<MailObject> readMail(String folderName, String uid) {
			return this.readMail(folderName, uid, Boolean.FALSE);
		}

		/**
		 * Read mail optional.
		 *
		 * @param folderName 	the folder name
		 * @param uid        	the uid
		 * @param detail 		read mail detail
		 * @return the optional
		 */
		public Optional<MailObject> readMail(String folderName, String uid, boolean detail) {
			if (this.receiveOperator == null) {
				return Optional.empty();
			}
			try (Store store = connect(); Folder folder = openReadOnlyFolder(store, folderName)) {
				if (!folder.exists() || !folder.isOpen()) {
					return Optional.empty();
				}

				Message message = this.receiveOperator.readMessage(folder, uid);
				if (message != null) {
					return receiveMessage((MimeMessage) message, detail);
				}
			} catch (Exception e) {
				if (this.logger.isDebugEnabled()) {
					this.logger.debug("Receive Message Error! ", e);
				}
			}

			return Optional.empty();
		}

		/**
		 * Read mail list list.
		 *
		 * @param folderName the folder name
		 * @param uidArrays  the uid arrays
		 * @return the list
		 */
		public List<MailObject> readMailList(String folderName, String... uidArrays) {
			List<MailObject> mailList = new ArrayList<>();
			if (this.receiveOperator == null) {
				return mailList;
			}

			try (Store store = connect(); Folder folder = openReadOnlyFolder(store, folderName)) {
				if (!folder.exists() || !folder.isOpen()) {
					return mailList;
				}
				this.receiveOperator.readMessages(folder, uidArrays)
						.forEach(message ->
								receiveMessage((MimeMessage) message, Boolean.FALSE)
										.ifPresent(mailList::add));
			} catch (Exception e) {
				this.logger.error("Receive Message Error! ");
				if (this.logger.isDebugEnabled()) {
					this.logger.debug("Stack message: ", e);
				}
			}

			return mailList;
		}

		/**
		 * Set mails status as read by uid list
		 *
		 * @param folderName the folder name
		 * @param uidArrays  the uid arrays
		 * @return the boolean
		 */
		public boolean readMails(String folderName, String... uidArrays) {
			return this.flagMailsStatus(Flags.Flag.SEEN, Boolean.TRUE, folderName, uidArrays);
		}

		/**
		 * Set mails status as unread by uid list
		 *
		 * @param folderName the folder name
		 * @param uidArrays  the uid arrays
		 * @return the boolean
		 */
		public boolean unreadMails(String folderName, String... uidArrays) {
			return this.flagMailsStatus(Flags.Flag.SEEN, Boolean.FALSE, folderName, uidArrays);
		}

		/**
		 * Set mails status as answered by uid list
		 *
		 * @param folderName the folder name
		 * @param uidArrays  the uid arrays
		 * @return the boolean
		 */
		public boolean answerMails(String folderName, String... uidArrays) {
			return this.flagMailsStatus(Flags.Flag.ANSWERED, Boolean.TRUE, folderName, uidArrays);
		}

		/**
		 * Set mails status as deleted by uid list
		 *
		 * @param folderName the folder name
		 * @param uidArrays  the uid arrays
		 * @return the boolean
		 */
		public boolean deleteMails(String folderName, String... uidArrays) {
			return this.flagMailsStatus(Flags.Flag.DELETED, Boolean.TRUE, folderName, uidArrays);
		}

		/**
		 * Set mails status as not deleted by uid list
		 *
		 * @param folderName the folder name
		 * @param uidArrays  the uid arrays
		 * @return the boolean
		 */
		public boolean recoverMails(String folderName, String... uidArrays) {
			return this.flagMailsStatus(Flags.Flag.DELETED, Boolean.FALSE, folderName, uidArrays);
		}

		/**
		 * Set mails status as flagged by uid list
		 *
		 * @param folderName the folder name
		 * @param uidArrays  the uid arrays
		 * @return the boolean
		 */
		public boolean flagMails(String folderName, String... uidArrays) {
			return this.flagMailsStatus(Flags.Flag.FLAGGED, Boolean.TRUE, folderName, uidArrays);
		}

		/**
		 * Set mails status as not flagged by uid list
		 *
		 * @param folderName the folder name
		 * @param uidArrays  the uid arrays
		 * @return the boolean
		 */
		public boolean unflagMails(String folderName, String... uidArrays) {
			return this.flagMailsStatus(Flags.Flag.FLAGGED, Boolean.FALSE, folderName, uidArrays);
		}

		/**
		 * Flag mails boolean.
		 *
		 * @param flag      the flag
		 * @param status    the status
		 * @param uidArrays the uid arrays
		 * @return the boolean
		 */
		private boolean flagMailsStatus(Flags.Flag flag, boolean status, String folderName, String... uidArrays) {
			if (this.receiveOperator == null) {
				return Boolean.FALSE;
			}
			try (Store store = connect(); Folder folder = openFolder(store, Boolean.FALSE, folderName)) {

				if (!folder.exists() || !folder.isOpen()) {
					return Boolean.FALSE;
				}

				List<Message> messageList = this.receiveOperator.readMessages(folder, uidArrays);

				for (Message message : messageList) {
					message.setFlag(flag, status);
				}
				return true;
			} catch (Exception e) {
				if (this.logger.isDebugEnabled()) {
					this.logger.debug("Set message status error! ", e);
				}
				return Boolean.FALSE;
			}
		}

		/**
		 * Connect to mail server
		 * @return                      Store instance
		 * @throws MessagingException   connect failed
		 */
		private Store connect() throws MessagingException {
			Properties properties = this.receiveOperator.readConfig(this.receiveConfig);
			Session session =
					Session.getDefaultInstance(properties, new DefaultAuthenticator(this.userName, this.passWord));

			Store store = session.getStore(properties.getProperty("mail.store.protocol"));

			store.connect(this.receiveConfig.getHostName(), this.receiveConfig.getHostPort(),
					this.userName, this.passWord);
			return store;
		}

		/**
		 * Read mail info
		 * @param mimeMessage           MIME message instance
		 * @param detail                read detail
		 * @return                      Mail object instance
		 */
		private Optional<MailObject> receiveMessage(MimeMessage mimeMessage, boolean detail) {
			try {
				MailObject mailObject = new MailObject();
				List<String> receiveList = new ArrayList<>();
				Arrays.stream(mimeMessage.getRecipients(IMAPMessage.RecipientType.TO))
						.filter(address -> address instanceof InternetAddress)
						.forEach(address -> receiveList.add(((InternetAddress)address).getAddress().toLowerCase()));

				if (!receiveList.contains(this.userName)) {
					throw new MessagingException("Current account not in receive list! ");
				}

				mailObject.setReceiveAddress(receiveList);

				Folder folder = mimeMessage.getFolder();

				if (folder instanceof POP3Folder) {
					mailObject.setUid(((POP3Folder)folder).getUID(mimeMessage));
				} else if (folder instanceof IMAPFolder) {
					mailObject.setUid(Long.valueOf(((IMAPFolder)folder).getUID(mimeMessage)).toString());
				}
				String subject = mimeMessage.getSubject();

				if (subject != null) {
					mailObject.setSubject(MimeUtility.decodeText(mimeMessage.getSubject()));
				} else {
					mailObject.setSubject("");
				}
				mailObject.setSendDate(mimeMessage.getSentDate());
				mailObject.setSendAddress(MimeUtility.decodeText(InternetAddress.toString(mimeMessage.getFrom())));

				if (detail) {
					//	Read mail cc address
					Optional.ofNullable((InternetAddress[]) mimeMessage.getRecipients(Message.RecipientType.CC))
							.ifPresent(ccAddress -> {
								List<String> ccList = new ArrayList<>();
								Arrays.asList(ccAddress).forEach(address -> ccList.add(address.getAddress()));
								mailObject.setCcAddress(ccList);
							});

					//	Read mail bcc address
					Optional.ofNullable((InternetAddress[]) mimeMessage.getRecipients(Message.RecipientType.BCC))
							.ifPresent(bccAddress -> {
								List<String> bccList = new ArrayList<>();
								Arrays.asList(bccAddress).forEach(address -> bccList.add(address.getAddress()));
								mailObject.setBccAddress(bccList);
							});

					//	Read mail content message
					StringBuilder contentBuffer = new StringBuilder();
					getMailContent(mimeMessage, contentBuffer);
					mailObject.setContent(contentBuffer.toString());

					mailObject.setAttachFiles(getMailAttachment(mimeMessage));
				}

				return Optional.of(mailObject);
			} catch (MessagingException | IOException e) {
				if (this.logger.isDebugEnabled()) {
					this.logger.debug("Receive message error! ", e);
				}
				return Optional.empty();
			}
		}

		private List<String> getMailAttachment(Part part) throws MessagingException, IOException {
			List<String> saveFiles = new ArrayList<>();
			if (StringUtils.isEmpty(this.storagePath)) {
				throw new IOException("Save attach file path error! ");
			}
			if (part.isMimeType(Globals.DEFAULT_EMAIL_CONTENT_TYPE_MULTIPART)) {
				Multipart multipart = (Multipart) part.getContent();
				int count = multipart.getCount();
				for (int i = 0; i < count; i++) {
					Part bodyPart = multipart.getBodyPart(i);
					if (bodyPart.getFileName() != null) {
						String disposition = bodyPart.getDisposition();
						if (disposition != null
								&& (disposition.equals(Part.ATTACHMENT) || disposition.equals(Part.INLINE))) {
							String savePath = this.storagePath + Globals.DEFAULT_PAGE_SEPARATOR
									+ MimeUtility.decodeText(bodyPart.getFileName());
							boolean saveFile = FileUtils.saveFile(bodyPart.getInputStream(), savePath);
							if (saveFile) {
								saveFiles.add(savePath);
							}
						} else if (bodyPart.isMimeType(Globals.DEFAULT_EMAIL_CONTENT_TYPE_MULTIPART)) {
							saveFiles.addAll(getMailAttachment(bodyPart));
						}
					}
				}
			}
			return saveFiles;
		}
	}

	private static MimeMessage convert(Session session, MailObject mailObject) throws MessagingException {
		MimeMessage message = new MimeMessage(session);

		message.setSubject(mailObject.getSubject(), mailObject.getCharset());

		MimeMultipart mimeMultipart = new MimeMultipart();

		if (mailObject.getAttachFiles() != null) {
			for (String attachment : mailObject.getAttachFiles()) {
				MimeBodyPart mimeBodyPart = new MimeBodyPart();

				File file;

				try {
					file = FileUtils.getFile(attachment);
				} catch (FileNotFoundException e) {
					throw new MessagingException("Attachment file not found! ", e);
				}

				DataSource dataSource = new FileDataSource(file);

				mimeBodyPart.setFileName(StringUtils.getFilename(attachment));
				mimeBodyPart.setDataHandler(new DataHandler(dataSource));

				mimeMultipart.addBodyPart(mimeBodyPart, mimeMultipart.getCount());
			}
		}

		if (mailObject.getIncludeFiles() != null) {
			List<String> includeFiles = mailObject.getIncludeFiles();
			for (String filePath : includeFiles) {
				File file;
				MimeBodyPart mimeBodyPart;

				try {
					file = FileUtils.getFile(filePath);
					String fileName = StringUtils.getFilename(filePath);
					mimeBodyPart = new MimeBodyPart();
					DataHandler dataHandler =
							new DataHandler(new ByteArrayDataSource(file.toURI().toURL().openStream(),
									"application/octet-stream"));
					mimeBodyPart.setDataHandler(dataHandler);

					mimeBodyPart.setFileName(fileName);
					mimeBodyPart.setHeader("Content-ID", fileName);
				} catch (Exception e) {
					throw new MessagingException("Process include file error! ", e);
				}

				mimeMultipart.addBodyPart(mimeBodyPart, mimeMultipart.getCount());
			}
		}

		if (mailObject.getContent() != null) {
			String content = mailObject.getContent();

			if (mailObject.getContentMap() != null) {
				Map<String, String> argsMap = mailObject.getContentMap();

				for (Map.Entry<String, String> entry : argsMap.entrySet()) {
					content = StringUtils.replace(content, "###" + entry.getKey() + "###", entry.getValue());
				}
			}

			MimeBodyPart mimeBodyPart = new MimeBodyPart();
			mimeBodyPart.setContent(content, mailObject.getContentType() + "; charset=" + mailObject.getCharset());
			mimeMultipart.addBodyPart(mimeBodyPart, mimeMultipart.getCount());
		}

		message.setContent(mimeMultipart);
		message.setFrom(new InternetAddress(mailObject.getSendAddress()));

		if (mailObject.getReceiveAddress() == null || mailObject.getReceiveAddress().isEmpty()) {
			throw new MessagingException("Unknown receive address");
		}
		StringBuilder receiveAddress = new StringBuilder();
		mailObject.getReceiveAddress().forEach(address -> receiveAddress.append(",").append(address));
		message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(receiveAddress.substring(1)));

		if (mailObject.getCcAddress() != null && !mailObject.getCcAddress().isEmpty()) {
			StringBuilder ccAddress = new StringBuilder();
			mailObject.getCcAddress().forEach(address -> ccAddress.append(",").append(address));
			message.setRecipients(Message.RecipientType.CC, InternetAddress.parse(ccAddress.substring(1)));
		}

		if (mailObject.getBccAddress() != null && !mailObject.getBccAddress().isEmpty()) {
			StringBuilder bccAddress = new StringBuilder();
			mailObject.getBccAddress().forEach(address -> bccAddress.append(",").append(address));
			message.setRecipients(Message.RecipientType.BCC, InternetAddress.parse(bccAddress.substring(1)));
		}

		if (mailObject.getReplyAddress() != null && !mailObject.getReplyAddress().isEmpty()) {
			StringBuilder replyAddress = new StringBuilder();
			mailObject.getReplyAddress().forEach(address -> replyAddress.append(",").append(address));
			message.setReplyTo(InternetAddress.parse(replyAddress.substring(1)));
		} else {
			message.setReplyTo(InternetAddress.parse(mailObject.getSendAddress()));
		}
		message.setSentDate(mailObject.getSendDate() == null ? new Date() : mailObject.getSendDate());
		return message;
	}

	private static Folder openReadOnlyFolder(Store store, String folderName)
			throws MessagingException {
		return openFolder(store, Boolean.TRUE, folderName);
	}

	private static Folder openFolder(Store store, boolean readOnly, String folderName)
			throws MessagingException {
		Folder folder = store.getFolder(folderName);
		folder.open(readOnly ? Folder.READ_ONLY : Folder.READ_WRITE);
		return folder;
	}

	private static void getMailContent(Part part, StringBuilder contentBuffer)
			throws MessagingException, IOException {
		String contentType = part.getContentType();
		int nameIndex = contentType.indexOf("name");

		if (contentBuffer == null) {
			throw new IOException();
		}

		if (part.isMimeType(Globals.DEFAULT_EMAIL_CONTENT_TYPE_TEXT) && (nameIndex == -1)) {
			contentBuffer.append(part.getContent().toString());
		} else if (part.isMimeType(Globals.DEFAULT_EMAIL_CONTENT_TYPE_HTML) && (nameIndex == -1)) {
			contentBuffer.append(part.getContent().toString());
		} else if (part.isMimeType(Globals.DEFAULT_EMAIL_CONTENT_TYPE_MULTIPART)) {
			Multipart multipart = (Multipart) part.getContent();
			int count = multipart.getCount();
			for (int i = 0; i < count; i++) {
				getMailContent(multipart.getBodyPart(i), contentBuffer);
			}
		} else if (part.isMimeType(Globals.DEFAULT_EMAIL_CONTENT_TYPE_MESSAGE_RFC822)) {
			getMailContent((Part) part.getContent(), contentBuffer);
		}
	}
}
