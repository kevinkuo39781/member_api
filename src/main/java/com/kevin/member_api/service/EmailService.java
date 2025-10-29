package com.kevin.member_api.service;

import com.mailjet.client.ClientOptions;
import com.mailjet.client.MailjetClient;
import com.mailjet.client.MailjetRequest;
import com.mailjet.client.MailjetResponse;
import com.mailjet.client.errors.MailjetException;
import com.mailjet.client.resource.Emailv31;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailService.class);

    private final MailjetClient mailjetClient;

    @Value("${mailjet.from.email}")
    private String fromEmail;

    @Value("${mailjet.from.name}")
    private String fromName;

    public EmailService(
            @Value("${mailjet.api.key}") String apiKey,
            @Value("${mailjet.api.secret}") String apiSecret) {
        String sanitizedApiKey = sanitizeCredential("mailjet.api.key", apiKey);
        String sanitizedApiSecret = sanitizeCredential("mailjet.api.secret", apiSecret);

        ClientOptions options = ClientOptions.builder()
                .apiKey(sanitizedApiKey)
                .apiSecretKey(sanitizedApiSecret)
                .build();

        this.mailjetClient = new MailjetClient(options);
    }

    public void sendActivationEmail(String toEmail, String activationToken) {
        String subject = "請啟用您的帳號";

        // TODO 這專案暫時寫死不抽 Domain
        String activationUrl = "https://memberapi.dionysus.pro/auth/activate?token=" + activationToken;
        
        String htmlContent = String.format("""
            <h2>歡迎加入會員服務！</h2>
            <p>請點擊以下連結啟用您的帳號：</p>
            <p><a href="%s">啟用帳號</a></p>
            <p>此連結將在 24 小時後過期。</p>
            <p>如果您沒有註冊此帳號，請忽略此郵件。</p>
            """, activationUrl);

        String textContent = String.format("""
            歡迎加入會員服務！
            
            請複製以下連結到瀏覽器啟用您的帳號：
            %s
            
            此連結將在 24 小時後過期。
            如果您沒有註冊此帳號，請忽略此郵件。
            """, activationUrl);

        sendEmail(toEmail, subject, htmlContent, textContent);
    }

    public void sendOtpEmail(String toEmail, String otp) {
        String subject = "您的登入驗證碼";
        
        String htmlContent = String.format("""
            <h2>登入驗證碼</h2>
            <p>您的驗證碼是：<strong>%s</strong></p>
            <p>此驗證碼將在 10 分鐘後過期。</p>
            <p>如果您沒有嘗試登入，請忽略此郵件。</p>
            """, otp);

        String textContent = String.format("""
            登入驗證碼
            
            您的驗證碼是：%s
            
            此驗證碼將在 10 分鐘後過期。
            如果您沒有嘗試登入，請忽略此郵件。
            """, otp);

        sendEmail(toEmail, subject, htmlContent, textContent);
    }

    @Value("${email.service.enabled:true}")
    private boolean emailEnabled;

    private void sendEmail(String toEmail, String subject, String htmlContent, String textContent) {
        if (!emailEnabled) {
            logger.info("Email sending is disabled. Would have sent email to {} with subject '{}'", toEmail, subject);
            return;
        }
        try {
            MailjetRequest request = new MailjetRequest(Emailv31.resource)
                    .property(Emailv31.MESSAGES, new JSONArray()
                            .put(new JSONObject()
                                    .put(Emailv31.Message.FROM, new JSONObject()
                                            .put("Email", fromEmail)
                                            .put("Name", fromName))
                                    .put(Emailv31.Message.TO, new JSONArray()
                                            .put(new JSONObject()
                                                    .put("Email", toEmail)))
                                    .put(Emailv31.Message.SUBJECT, subject)
                                    .put(Emailv31.Message.TEXTPART, textContent)
                                    .put(Emailv31.Message.HTMLPART, htmlContent)));

            MailjetResponse response = mailjetClient.post(request);
            
            if (response.getStatus() == 200) {
                logger.info("Email sent successfully to: {}", toEmail);
            } else {
                logger.error("Failed to send email to: {}. Status: {}, Response: {}", 
                    toEmail, response.getStatus(), response.getData());
            }
            
        } catch (MailjetException e) {
            logger.error("Error sending email to: " + toEmail, e);
            throw new RuntimeException("Failed to send email", e);
        }
    }

    private String sanitizeCredential(String propertyName, String value) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalStateException("Missing Mailjet credential: " + propertyName);
        }
        return value.trim();
    }
}
