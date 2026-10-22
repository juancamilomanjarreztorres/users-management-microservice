package com.jcaa.usersmanagement.infrastructure.security;

import com.jcaa.usersmanagement.domain.enums.UserRole;
import com.jcaa.usersmanagement.domain.model.UserModel;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenService {

  private static final String ROLE_CLAIM = "role";

  private final SecretKey signingKey;
  private final long expirationSeconds;
  private final Clock clock;

  @Autowired
  public JwtTokenService(final JwtProperties properties) {
    this(properties, Clock.systemUTC());
  }

  JwtTokenService(final JwtProperties properties, final Clock clock) {
    String secret = properties.secret();
    // Si el secreto no viene configurado o está vacío, usamos uno por defecto seguro en Base64 (de más de 32 bytes)
    if (secret == null || secret.trim().isEmpty()) {
      secret = "VGhpcyJzUEFTU1dPUkRJcyN2ZXJ5U2VjdXJlQW5kTG9uZ0Vub3VnaFRvUGFzc0pXVFNlY3VyZVRlc3Q=";
    }
    this.signingKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret));
    this.expirationSeconds = properties.expirationSeconds() > 0 ? properties.expirationSeconds() : 900;
    this.clock = clock;
  }

  public String generate(final UserModel user) {
    final Instant issuedAt = clock.instant();
    final Instant expiration = issuedAt.plusSeconds(expirationSeconds);
    return Jwts.builder()
        .subject(user.getId().value())
        .claim(ROLE_CLAIM, user.getRole().name())
        .issuedAt(Date.from(issuedAt))
        .expiration(Date.from(expiration))
        .signWith(signingKey)
        .compact();
  }

  public JwtPrincipal parse(final String token) {
    final Claims claims =
        Jwts.parser()
            .verifyWith(signingKey)
            .clock(() -> Date.from(clock.instant()))
            .build()
            .parseSignedClaims(token)
            .getPayload();
    return new JwtPrincipal(claims.getSubject(), UserRole.fromString(claims.get(ROLE_CLAIM, String.class)));
  }

  public long expirationSeconds() {
    return expirationSeconds;
  }
}
