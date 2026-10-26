package com.jcaa.usersmanagement.infrastructure.security;

import java.util.List;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityConfig {

  private static final String AUTH_LOGIN_PATH = "/api/auth/login";
  private static final String USERS_PATH = "/api/users";
  private static final String USERS_DETAIL_PATH = "/api/users/**";

  private static final String[] OPEN_API_PATHS = {
          "/swagger-ui/**",
          "/swagger-ui.html",
          "/v3/api-docs/**"
  };

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();

    configuration.setAllowedOrigins(List.of(
            "http://127.0.0.1:5500",
            "http://localhost:5500"
    ));

    configuration.setAllowedMethods(List.of(
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS"
    ));

    configuration.setAllowedHeaders(List.of(
            "Authorization",
            "Content-Type",
            "Accept"
    ));

    configuration.setAllowCredentials(false);
    configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source =
            new UrlBasedCorsConfigurationSource();

    source.registerCorsConfiguration("/**", configuration);

    return source;
  }

  @Bean
  public SecurityFilterChain securityFilterChain(
          final HttpSecurity http,
          final JwtAuthenticationFilter jwtAuthenticationFilter,
          final RestAuthenticationEntryPoint authenticationEntryPoint,
          final RestAccessDeniedHandler accessDeniedHandler,
          final CorsConfigurationSource corsConfigurationSource)
          throws Exception {

    http
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .csrf(csrf -> csrf.disable())
            .httpBasic(httpBasic -> httpBasic.disable())
            .formLogin(formLogin -> formLogin.disable())
            .sessionManagement(
                    session -> session.sessionCreationPolicy(
                            SessionCreationPolicy.STATELESS))
            .exceptionHandling(
                    handling -> handling
                            .authenticationEntryPoint(authenticationEntryPoint)
                            .accessDeniedHandler(accessDeniedHandler))
            .authorizeHttpRequests(
                    authorization -> authorization
                            .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                            .requestMatchers(AUTH_LOGIN_PATH).permitAll()
                            .requestMatchers(OPEN_API_PATHS).permitAll()
                            .requestMatchers(HttpMethod.POST, USERS_PATH).permitAll()
                            .requestMatchers(
                                    HttpMethod.GET,
                                    USERS_PATH,
                                    USERS_DETAIL_PATH)
                            .hasAnyRole("ADMIN", "REVIEWER")
                            .requestMatchers(HttpMethod.PUT, USERS_DETAIL_PATH)
                            .hasRole("ADMIN")
                            .requestMatchers(HttpMethod.DELETE, USERS_DETAIL_PATH)
                            .hasRole("ADMIN")
                            .anyRequest().authenticated())
            .addFilterBefore(
                    jwtAuthenticationFilter,
                    UsernamePasswordAuthenticationFilter.class);

    return http.build();
  }
}

