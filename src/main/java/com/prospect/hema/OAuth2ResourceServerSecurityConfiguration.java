package com.prospect.hema;

/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

            import java.io.IOException;
            import java.util.Arrays;

            import org.keycloak.adapters.authorization.integration.jakarta.ServletPolicyEnforcerFilter;
            import org.keycloak.adapters.authorization.spi.ConfigurationResolver;
            import org.keycloak.adapters.authorization.spi.HttpRequest;
            import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
            import org.keycloak.util.JsonSerialization;
            import org.springframework.beans.factory.annotation.Value;
            import org.springframework.context.annotation.Bean;
            import org.springframework.context.annotation.Configuration;
            import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
            import org.springframework.security.config.annotation.web.builders.HttpSecurity;
            import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
            import org.springframework.security.config.http.SessionCreationPolicy;
            import org.springframework.security.oauth2.jwt.JwtDecoder;
            import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
            import org.springframework.security.web.SecurityFilterChain;
            import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
            import org.springframework.web.cors.CorsConfiguration;
            import org.springframework.web.cors.CorsConfigurationSource;
            import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * OAuth resource configuration.
 *
 * @author Josh Cummings
 */

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class OAuth2ResourceServerSecurityConfiguration {

    // Injected JwtAuthConverter bean
    private final JwtAuthConverter jwtAuthConverter;
    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    String jwkSetUri;

    public OAuth2ResourceServerSecurityConfiguration(JwtAuthConverter jwtAuthConverter) {
        this.jwtAuthConverter = jwtAuthConverter;
    }

    // Injected JwtAuthConverter bean
    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                // Authorize requests based on different conditions
                .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                        // Specify a pattern and required roles for certain URLs
                     //   .requestMatchers(new AntPathRequestMatcher("/allylabo/**")).hasAnyRole("developer", "admin")
                    //    .requestMatchers(new AntPathRequestMatcher("/mum/**")).hasRole("Labo")
                        .requestMatchers(new AntPathRequestMatcher("/ddd/**")).hasRole("user")

                        // For any other request, authentication is required
                        .anyRequest().authenticated())
                // Configure OAuth2 Resource Server with JWT authentication
                .oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter)))
                // Configure session management to be stateless
                .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // Configure Cross-Origin Resource Sharing (CORS)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // Build the SecurityFilterChain
                .build();
    }
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        // Create a CorsConfiguration with allowed origins, methods, and headers
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));
        corsConfiguration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));

        // Create a UrlBasedCorsConfigurationSource and register the CorsConfiguration for all paths
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);

        // Return the configured CorsConfigurationSource
        return source;
    }

    private ServletPolicyEnforcerFilter createPolicyEnforcerFilter() {
        return new ServletPolicyEnforcerFilter(new ConfigurationResolver() {
            @Override
            public PolicyEnforcerConfig resolve(HttpRequest request) {
                try {
                    return JsonSerialization.readValue(getClass().getResourceAsStream("/policy-enforcer.json"), PolicyEnforcerConfig.class);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        });
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(this.jwkSetUri).build();
    }

}
