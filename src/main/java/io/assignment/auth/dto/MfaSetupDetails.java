package io.assignment.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class MfaSetupDetails {
    private final String secret;
    private final String qrDataUriLabel;
}
