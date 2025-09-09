package io.assignment.auth.config;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import com.google.zxing.qrcode.QRCodeWriter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;

@Configuration
public class TotpConfig {

    @Bean
    public TimeBasedOneTimePasswordGenerator timeBasedOneTimePasswordGenerator() throws NoSuchAlgorithmException {
        // 30s window, 6 digits, HmacSHA256
        return new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30), 6, "HmacSHA256");
    }

    @Bean
    public KeyGenerator secretKeyGenerator() throws NoSuchAlgorithmException {
        // Secret key for HmacSHA256
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
        keyGenerator.init(256);
        return keyGenerator;
    }

    @Bean
    public QRCodeWriter qrCodeWriter() {
        return new QRCodeWriter();
    }
}

