package io.github.brenomega.authkit.infrastructure.security;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;

@Configuration
public class WebAuthnConfig {

    @Bean
    public RelyingParty relyingParty(AuthProperties authProperties, CredentialRepository credentialRepository) {
        AuthProperties.Passkey passkey = authProperties.getPasskey();
        RelyingPartyIdentity identity = RelyingPartyIdentity.builder()
                .id(passkey.getRpId())
                .name(passkey.getRpName())
                .build();

        return RelyingParty.builder()
                .identity(identity)
                .credentialRepository(credentialRepository)
                .origins(parseOrigins(passkey.getOrigins()))
                .allowOriginPort(passkey.isAllowOriginPort())
                .allowOriginSubdomain(passkey.isAllowOriginSubdomain())
                .allowUntrustedAttestation(true)
                .validateSignatureCounter(true)
                .build();
    }

    private Set<String> parseOrigins(String origins) {
        return Arrays.stream(origins.split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .collect(Collectors.toUnmodifiableSet());
    }
}
