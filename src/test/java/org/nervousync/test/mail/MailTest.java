package org.nervousync.test.mail;

import org.junit.jupiter.api.*;
import org.nervousync.commons.Globals;
import org.nervousync.configs.ConfigureManager;
import org.nervousync.enumerations.mail.MailProtocol;
import org.nervousync.exceptions.builder.BuilderException;
import org.nervousync.mail.MailObject;
import org.nervousync.mail.config.MailConfig;
import org.nervousync.mail.config.MailConfigBuilder;
import org.nervousync.security.factory.SecureFactory;
import org.nervousync.test.BaseTest;
import org.nervousync.utils.*;

import java.net.Proxy;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;
import java.util.Properties;

public final class MailTest extends BaseTest {

	private static final String MAIL_SUBJECT =
			MultilingualUtils.newAgent(MailTest.class).findMessage("Mail_Subject");
	private static final String MAIL_CONTENT =
			MultilingualUtils.newAgent(MailTest.class).findMessage("Mail_Content");

	private static Properties PROPERTIES = null;
	private static ConfigureManager CONFIGURE_MANAGER = null;

	private static boolean SKIP_TEST = Boolean.FALSE;

	@BeforeAll
	public static void initialize() {
		SKIP_TEST = !FileUtils.isExists("src/test/resources/mail.xml");
		CONFIGURE_MANAGER = ConfigureManager.getInstance();
	}

	@AfterAll
	public static void clear() {
		CONFIGURE_MANAGER.removeConfigure(MailConfig.class);
		CONFIGURE_MANAGER.removeConfigure(SecureFactory.class);
	}

	@Test
	@Order(0)
	public void generateConfig() throws BuilderException {
		if (SKIP_TEST) {
			return;
		}
		SecureFactory.systemConfig(SecureFactory.SecureAlgorithm.SM4);
		long currentTime = DateTimeUtils.currentUTCTimeMillis();
		KeyPair keyPair = SecurityUtils.RSAKeyPair(1024);
		X509Certificate x509Certificate = CertificateUtils.x509(keyPair.getPublic(), IDUtils.snowflake(),
				new Date(currentTime), new Date(currentTime + 365 * 24 * 60 * 60 * 1000L), "TestCert", keyPair.getPrivate(), "SHA1withRSA");
		PROPERTIES = PropertiesUtils.loadProperties("src/test/resources/mail.xml");
		MailConfig mailConfig = MailConfigBuilder.newBuilder()
				.sendConfig()
				.mailProtocol(MailProtocol.SMTP)
				.configHost(PROPERTIES.getProperty("config.send.address"),
						Integer.parseInt(PROPERTIES.getProperty("config.send.port")))
				.authLogin(Boolean.parseBoolean(PROPERTIES.getProperty("config.send.auth")))
				.useSSL(Boolean.parseBoolean(PROPERTIES.getProperty("config.send.ssl")))
				.connectionTimeout(10)
				.processTimeout(10)
				.confirmParent(MailConfigBuilder.class)
				.proxyConfig()
				.proxyType(Proxy.Type.SOCKS)
				.serverConfig("127.0.0.1", 1080)
				.authenticator(PROPERTIES.getProperty("config.userName"), PROPERTIES.getProperty("config.passWord"))
				.confirmParent(MailConfigBuilder.class)
				.receiveConfig()
				.mailProtocol(MailProtocol.valueOf(PROPERTIES.getProperty("config.receive.protocol")))
				.configHost(PROPERTIES.getProperty("config.receive.address"),
						Integer.parseInt(PROPERTIES.getProperty("config.receive.port")))
				.authLogin(Boolean.parseBoolean(PROPERTIES.getProperty("config.receive.auth")))
				.useSSL(Boolean.parseBoolean(PROPERTIES.getProperty("config.receive.ssl")))
				.confirmParent(MailConfigBuilder.class)
				.authentication(PROPERTIES.getProperty("config.userName"), PROPERTIES.getProperty("config.passWord"))
				.storagePath(PROPERTIES.getProperty("config.storagePath"))
				.signer(x509Certificate, keyPair.getPrivate())
				.confirm();
		String xmlContent = mailConfig.toXML(Boolean.TRUE);
		this.logger.info("Mail_Generate_Config_Info", xmlContent);
		MailConfig parseConfig = StringUtils.stringToObject(xmlContent, MailConfig.class, "https://nervousync.org/schemas/mail");
		this.logger.info("Mail_Parse_Config_Info", parseConfig.toFormattedJson());
		CONFIGURE_MANAGER.saveConfigure(mailConfig);
		Optional.ofNullable(CONFIGURE_MANAGER.readConfigure(MailConfig.class))
				.ifPresent(readConfig -> this.logger.info("Mail_Parse_Config_Info", readConfig.toFormattedJson()));
	}

	@Test
	@Order(10)
	public void folderList() {
		if (SKIP_TEST) {
			return;
		}
		Optional.ofNullable(CONFIGURE_MANAGER)
				.map(manager -> manager.readConfigure(MailConfig.class))
				.ifPresent(mailCOnfig -> {
					MailUtils.Agent mailAgent = MailUtils.mailAgent(mailCOnfig);
					Assertions.assertNotNull(mailAgent);
					mailAgent.folderList().forEach(this.logger::info);
				});
	}

	@Test
	@Order(20)
	public void sendMail() {
		if (SKIP_TEST) {
			return;
		}
		Optional.ofNullable(CONFIGURE_MANAGER)
				.map(manager -> manager.readConfigure(MailConfig.class))
				.ifPresent(mailCOnfig -> {
					MailUtils.Agent mailAgent = MailUtils.mailAgent(mailCOnfig);
					Assertions.assertNotNull(mailAgent);
					this.logger.info("Mail_Count", mailAgent.mailCount());
					MailObject mailObject = new MailObject();
					Optional.ofNullable(PROPERTIES.getProperty("mail.sender")).ifPresent(mailObject::setSendAddress);
					Optional.ofNullable(PROPERTIES.getProperty("mail.receiver"))
							.flatMap(receiver -> Optional.of(StringUtils.tokenizeToStringArray(receiver, "|")))
							.ifPresent(receiveAddress -> mailObject.setReceiveAddress(Arrays.asList(receiveAddress)));
					Optional.ofNullable(PROPERTIES.getProperty("mail.cc"))
							.flatMap(receiver -> Optional.of(StringUtils.tokenizeToStringArray(receiver, "|")))
							.ifPresent(receiveAddress -> mailObject.setCcAddress(Arrays.asList(receiveAddress)));
					Optional.ofNullable(PROPERTIES.getProperty("mail.bcc"))
							.flatMap(receiver -> Optional.of(StringUtils.tokenizeToStringArray(receiver, "|")))
							.ifPresent(receiveAddress -> mailObject.setBccAddress(Arrays.asList(receiveAddress)));
					Optional.ofNullable(PROPERTIES.getProperty("mail.replies"))
							.flatMap(replies -> Optional.of(StringUtils.tokenizeToStringArray(replies, "|")))
							.ifPresent(replyAddress -> mailObject.setReplyAddress(Arrays.asList(replyAddress)));
					Optional.ofNullable(PROPERTIES.getProperty("mail.attaches"))
							.flatMap(attaches -> Optional.of(StringUtils.tokenizeToStringArray(attaches, "|")))
							.ifPresent(attacheFiles -> mailObject.setAttachFiles(Arrays.asList(attacheFiles)));
					mailObject.setSubject(MAIL_SUBJECT);
					mailObject.setContent(MAIL_CONTENT);
					this.logger.info("Mail_Sent_Result", mailAgent.sendMail(mailObject));
				});
	}

	@Test
	@Order(30)
	public void receiveMail() {
		if (SKIP_TEST) {
			return;
		}
		Optional.ofNullable(CONFIGURE_MANAGER)
				.map(manager -> manager.readConfigure(MailConfig.class))
				.ifPresent(mailCOnfig -> {
					MailUtils.Agent mailAgent = MailUtils.mailAgent(mailCOnfig);
					Assertions.assertNotNull(mailAgent);
					mailAgent.mailList(Globals.DEFAULT_EMAIL_FOLDER_INBOX)
							.stream()
							.filter(uid ->
									Optional.ofNullable(mailAgent.readMail(Globals.DEFAULT_EMAIL_FOLDER_INBOX, uid))
											.map(receiveObject -> MAIL_SUBJECT.equalsIgnoreCase(receiveObject.getSubject()))
											.orElse(Boolean.FALSE))
							.forEach(uid ->
									Optional.ofNullable(mailAgent.readMail(Globals.DEFAULT_EMAIL_FOLDER_INBOX, uid, Boolean.TRUE))
											.ifPresent(receiveObject -> {
												this.logger.info("Mail_Info_UID", receiveObject.getUid());
												this.logger.info("Mail_Info_Title", receiveObject.getSubject());
												this.logger.info("Mail_Info_Content", receiveObject.getContent());
												receiveObject.getAttachFiles().forEach(filePath -> {
													this.logger.info(filePath);
													FileUtils.removeFile(filePath);
												});
											}));
				});
	}

	@Test
	@Order(40)
	public void flagMail() {
		if (SKIP_TEST) {
			return;
		}
		Optional.ofNullable(CONFIGURE_MANAGER)
				.map(manager -> manager.readConfigure(MailConfig.class))
				.ifPresent(mailCOnfig -> {
					MailUtils.Agent mailAgent = MailUtils.mailAgent(mailCOnfig);
					Assertions.assertNotNull(mailAgent);
					mailAgent.mailList(Globals.DEFAULT_EMAIL_FOLDER_INBOX)
							.stream()
							.filter(uid ->
									Optional.ofNullable(mailAgent.readMail(Globals.DEFAULT_EMAIL_FOLDER_INBOX, uid))
											.map(receiveObject -> MAIL_SUBJECT.equalsIgnoreCase(receiveObject.getSubject()))
											.orElse(Boolean.FALSE))
							.forEach(uid -> {
								this.logger.info("Mail_Flag_Read",
										mailAgent.readMails(Globals.DEFAULT_EMAIL_FOLDER_INBOX, uid));
								this.logger.info("Mail_Flag_UnRead",
										mailAgent.unreadMails(Globals.DEFAULT_EMAIL_FOLDER_INBOX, uid));
								this.logger.info("Mail_Flag_Reply",
										mailAgent.answerMails(Globals.DEFAULT_EMAIL_FOLDER_INBOX, uid));
								this.logger.info("Mail_Flag_Flag",
										mailAgent.flagMails(Globals.DEFAULT_EMAIL_FOLDER_INBOX, uid));
								this.logger.info("Mail_Flag_UnFlag",
										mailAgent.unflagMails(Globals.DEFAULT_EMAIL_FOLDER_INBOX, uid));
								this.logger.info("Mail_Flag_Delete",
										mailAgent.deleteMails(Globals.DEFAULT_EMAIL_FOLDER_INBOX, uid));
							});
				});
	}

	@Test
	@Order(50)
	public void recoveryMail() {
		if (SKIP_TEST) {
			return;
		}
		Optional.ofNullable(CONFIGURE_MANAGER)
				.map(manager -> manager.readConfigure(MailConfig.class))
				.ifPresent(mailCOnfig -> {
					MailUtils.Agent mailAgent = MailUtils.mailAgent(mailCOnfig);
					Assertions.assertNotNull(mailAgent);
					mailAgent.mailList(Globals.DEFAULT_EMAIL_FOLDER_TRASH)
							.stream()
							.filter(uid ->
									Optional.ofNullable(mailAgent.readMail(Globals.DEFAULT_EMAIL_FOLDER_TRASH, uid))
											.map(receiveObject -> MAIL_SUBJECT.equalsIgnoreCase(receiveObject.getSubject()))
											.orElse(Boolean.FALSE))
							.forEach(uid ->
									this.logger.info("Mail_Recovery", uid,
											mailAgent.recoverMails(Globals.DEFAULT_EMAIL_FOLDER_TRASH, uid)));
				});
	}

	@Test
	@Order(60)
	public void dropMail() {
		if (SKIP_TEST) {
			return;
		}
		Optional.ofNullable(CONFIGURE_MANAGER)
				.map(manager -> manager.readConfigure(MailConfig.class))
				.ifPresent(mailCOnfig -> {
					MailUtils.Agent mailAgent = MailUtils.mailAgent(mailCOnfig);
					Assertions.assertNotNull(mailAgent);
					mailAgent.mailList(Globals.DEFAULT_EMAIL_FOLDER_INBOX)
							.stream()
							.filter(uid ->
									Optional.ofNullable(mailAgent.readMail(Globals.DEFAULT_EMAIL_FOLDER_INBOX, uid))
											.map(receiveObject -> MAIL_SUBJECT.equalsIgnoreCase(receiveObject.getSubject()))
											.orElse(Boolean.FALSE))
							.forEach(uid ->
									this.logger.info("Mail_Flag_Delete",
											mailAgent.deleteMails(Globals.DEFAULT_EMAIL_FOLDER_INBOX, uid)));
					mailAgent.mailList(Globals.DEFAULT_EMAIL_FOLDER_TRASH).stream().filter(uid ->
									Optional.ofNullable(mailAgent.readMail(Globals.DEFAULT_EMAIL_FOLDER_TRASH, uid))
											.map(receiveObject -> MAIL_SUBJECT.equalsIgnoreCase(receiveObject.getSubject()))
											.orElse(Boolean.FALSE))
							.forEach(uid ->
									this.logger.info("Mail_Drop", uid,
											mailAgent.deleteMails(Globals.DEFAULT_EMAIL_FOLDER_TRASH, uid)));
				});
	}

	@Test
	@Order(70)
	public void mailCount() {
		if (SKIP_TEST) {
			return;
		}
		Optional.ofNullable(CONFIGURE_MANAGER)
				.map(manager -> manager.readConfigure(MailConfig.class))
				.ifPresent(mailCOnfig -> {
					MailUtils.Agent mailAgent = MailUtils.mailAgent(mailCOnfig);
					Assertions.assertNotNull(mailAgent);
					this.logger.info("Inbox_Count", mailAgent.mailCount(Globals.DEFAULT_EMAIL_FOLDER_INBOX));
					this.logger.info("Spam_Count: {}", mailAgent.mailCount(Globals.DEFAULT_EMAIL_FOLDER_SPAM));
					this.logger.info("Drafts_Count: {}", mailAgent.mailCount(Globals.DEFAULT_EMAIL_FOLDER_DRAFTS));
					this.logger.info("Send_Count: {}", mailAgent.mailCount(Globals.DEFAULT_EMAIL_FOLDER_SENT));
					this.logger.info("Trash_Count: {}", mailAgent.mailCount(Globals.DEFAULT_EMAIL_FOLDER_TRASH));
				});
	}
}
