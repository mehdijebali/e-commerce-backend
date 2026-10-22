package ecommerce.config;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

import java.nio.charset.StandardCharsets;

@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        AuthenticationEntryPoint entryPoint = friendly401EntryPoint();

        // protect endpoint /api/orders
        http.authorizeHttpRequests(requests -> requests
                        .requestMatchers("/api/orders/**").authenticated()
                        .anyRequest().permitAll())
                // validate Auth0 JWT access tokens
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(Customizer.withDefaults())
                        .authenticationEntryPoint(entryPoint))
                // same entry point when no token is sent at all
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(entryPoint))
                // use the CORS mappings defined in MyAppConfig / MyDataRestConfig
                .cors(Customizer.withDefaults())
                // stateless REST API: no sessions, no CSRF tokens
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable());

        return http.build();
    }

    // force a non-empty JSON response body for 401's (default is an empty body)
    private AuthenticationEntryPoint friendly401EntryPoint() {
        BearerTokenAuthenticationEntryPoint bearerEntryPoint = new BearerTokenAuthenticationEntryPoint();

        return (request, response, authException) -> {
            // keep the standard 401 status and WWW-Authenticate header
            bearerEntryPoint.commence(request, response, authException);

            String message = request.getHeader("Authorization") == null
                    ? "Full authentication is required to access this resource"
                    : "Invalid or expired access token";

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.getWriter().write(
                    "{\"status\":401,\"error\":\"Unauthorized\",\"message\":\"%s\",\"path\":\"%s\"}"
                            .formatted(message, escapeJson(request.getRequestURI())));
        };
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
