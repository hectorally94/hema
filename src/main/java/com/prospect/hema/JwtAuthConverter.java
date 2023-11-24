package com.prospect.hema;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    // Converter to extract authorities from the JWT
    private static final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    // Resource ID and Principal Attribute properties, injected from application.properties
    @Value("${jwt.auth.converter.resource-id}")
    private String resourceId;

    @Value("${jwt.auth.converter.principal-attribute}")
    private String principalAttribute;

    // Conversion method to convert a JWT to an AbstractAuthenticationToken
    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        // Combine authorities from JwtGrantedAuthoritiesConverter and resource roles
        Collection<GrantedAuthority> authorities =
                Stream.concat(jwtGrantedAuthoritiesConverter.convert(jwt).stream(),extractRealmRoles(jwt).stream())
                        .collect(Collectors.toSet());
        // Use the principal attribute from the JWT claims (default to 'sub' if not specified)
        String claimName = principalAttribute == null ? JwtClaimNames.SUB : principalAttribute;
        // Create JwtAuthenticationToken with authorities and principal
        return new JwtAuthenticationToken(jwt, authorities, jwt.getClaim(claimName));
    }

  /*  // Extract roles from the 'resource_access' claim in the JWT
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess = jwt.getClaim("resource_access");
        Map<String, Object> resource;
        Collection<String> resourceRoles;
        // Check if 'resource_access' and resource for the specified ID are present
        if (resourceAccess == null
                || (resource = (Map<String, Object>) resourceAccess.get(resourceId)) == null
                || (resourceRoles = (Collection<String>) resource.get("roles")) == null) {
            // Return an empty set if the roles are not found
            return Set.of();
        }
        // Map roles to SimpleGrantedAuthority objects with 'ROLE_' prefix
        return resourceRoles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    } */
  private Collection<? extends GrantedAuthority> extractRealmRoles(Jwt jwt) {
      // Get the 'realm_access' claim from the JWT
      Map<String, Object> realmAccess = jwt.getClaim("realm_access");

      Collection<String> realmRoles;

      // Check if 'realm_access' and roles are present
      if (realmAccess == null || (realmRoles = (Collection<String>) realmAccess.get("roles")) == null) {
          // Return an empty set if the roles are not found
          return Set.of();
      }

      // Map roles to SimpleGrantedAuthority objects with 'ROLE_' prefix
      return realmRoles.stream()
              .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
              .collect(Collectors.toSet());
  }

}
