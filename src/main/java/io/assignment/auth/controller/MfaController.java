package io.assignment.auth.controller;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import io.assignment.auth.api.MfaApi;
import io.assignment.auth.dto.MfaSetupResponse;
import io.assignment.auth.dto.UserPrincipal;
import io.assignment.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base32;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RestController
@RequiredArgsConstructor
public class MfaController implements MfaApi {

    private final AuthService authService;
    private final QRCodeWriter qrCodeWriter;

    @Override
    public ResponseEntity<MfaSetupResponse> authMfaSetupPost() {
        UserPrincipal principal = (UserPrincipal) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        try {
            var mfaDetails = authService.setupMfa(principal.getId());
            String base64Secret = mfaDetails.getSecret();
            String qrLabel = mfaDetails.getQrDataUriLabel();

            byte[] secretBytes = Base64.getDecoder().decode(base64Secret);
            String base32Secret = new Base32().encodeToString(secretBytes);
            String issuer = URLEncoder.encode("AuthService", StandardCharsets.UTF_8).replace("+", "%20");
            String otpAuthUri = String.format("otpauth://totp/%s?secret=%s&issuer=%s",
                    URLEncoder.encode(qrLabel, StandardCharsets.UTF_8).replace("+", "%20"),
                    base32Secret,
                    issuer);

            BitMatrix bitMatrix = qrCodeWriter.encode(otpAuthUri, BarcodeFormat.QR_CODE, 200, 200);
            ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);
            byte[] pngData = pngOutputStream.toByteArray();

            String qrDataUri = String.format("data:image/png;base64,%s", Base64.getEncoder().encodeToString(pngData));
            return ResponseEntity.ok(new MfaSetupResponse().qrDataUri(qrDataUri));
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate MFA QR code", e);
        }
    }
}

