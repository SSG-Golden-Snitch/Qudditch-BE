package com.goldensnitch.qudditch.service;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.sendgrid.Method;
import com.sendgrid.Request;
import com.sendgrid.Response;
import com.sendgrid.SendGrid;
import com.sendgrid.helpers.mail.Mail;
import com.sendgrid.helpers.mail.objects.Content;
import com.sendgrid.helpers.mail.objects.Email;

import lombok.extern.slf4j.Slf4j;



/* @Slf4j
@Service
public class EmailService {
    private final SendGrid sendGrid;
    private final String fromEmail;

    public EmailService(
            // get the SendGrid bean automatically created by Spring Boot
            @Autowired SendGrid sendGrid,
            // read your email to use as sender from application.properties
            @Value("${twilio.sendgrid.from-email}") String fromEmail
    ) {
        this.sendGrid = sendGrid;
        this.fromEmail = fromEmail;
    }

    public void sendSingleEmail(String toEmail) {
        Email from = new Email(this.fromEmail);
        String subject = "Hello, World!";
        Email to = new Email(toEmail);
        Content content = new Content("text/plain", "Welcome to the Twilio SendGrid world!");

        Mail mail = new Mail(from, subject, to, content);

        sendEmail(mail);
    }

    private void sendEmail(Mail mail) {
        try {
            Request request = new Request();
            request.setMethod(Method.POST);
            request.setEndpoint("mail/send");
            request.setBody(mail.build());

            Response response = sendGrid.api(request);
            int statusCode = response.getStatusCode();
            if (statusCode < 200 || statusCode >= 300) {
                throw new RuntimeException(response.getBody());
            }
        } catch (IOException e) {
            log.error("Error sending email", e);
            throw new RuntimeException(e.getMessage());
        }
    }
} */
@Slf4j
@Service
public class EmailService {
    private final SendGrid sendGrid;
    private final String fromEmail;

    @Autowired
    public EmailService(@Value("${spring.sendgrid.api-key}") String apiKey,
                        @Value("${twilio.sendgrid.from-email}") String fromEmail) {
        this.sendGrid = new SendGrid(apiKey);
        this.fromEmail = fromEmail;
    }

    public void sendVerificationEmail(String toEmail, String verificationCode) throws IOException {
        try {
            String subject = "계정 인증을 완료해주세요";
            String verificationUrl = String.format("https://yourdomain.com/verify?code=%s", verificationCode);
            String contentText = String.format("<html><body><p>아래 링크를 클릭하여 계정 인증을 완료해주세요:</p>" +
                                            "<a href=\"%s\">계정 인증하기</a></body></html>", verificationUrl);
            Email from = new Email(this.fromEmail);
            Email to = new Email(toEmail);
            Content content = new Content("text/html", contentText);
            Mail mail = new Mail(from, subject, to, content);

            sendEmail(mail);
        } catch (Exception e) {
            log.error("Verification email sending failed for email {}: {}", toEmail, e.getMessage());
            throw e; // Re-throw the exception to ensure the calling method can handle it
        }
    }
    
    // 비밀번호 재설정 이메일을 전송하는 메서드
    public void sendPasswordResetEmail(String toEmail, String temporaryPassword) throws IOException {
        String subject = "비밀번호 재설정 요청"; // 이메일 제목
        String contentText = "다음은 임시 비밀번호입니다: " + temporaryPassword +
                            "\n로그인 후 비밀번호를 변경해주세요."; // 이메일 내용
        
        Email from = new Email(this.fromEmail);
        Email to = new Email(toEmail);
        Content content = new Content("text/plain", contentText);
        Mail mail = new Mail(from, subject, to, content);

        sendEmail(mail); // 메일 전송
    }

    // 메일을 실제로 전송하는 메서드
    private void sendEmail(Mail mail) throws IOException {
        Request request = new Request();
        request.setMethod(Method.POST);
        request.setEndpoint("mail/send");
        request.setBody(mail.build());

        Response response = sendGrid.api(request);
        if (response.getStatusCode() != 202) {
            log.error("이메일 전송 실패: {}, body: {}", response.getStatusCode(), response.getBody());
            throw new RuntimeException("이메일 전송 실패: 상태 코드 " + response.getStatusCode());
        }
    }

    // 인증 코드 생성 메소드
    private String generateVerificationCode(int length) {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        StringBuilder result = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            int index = (int) (Math.random() * characters.length());
            result.append(characters.charAt(index));
        }
        return result.toString();
    }
}
    