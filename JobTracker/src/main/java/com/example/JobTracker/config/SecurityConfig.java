package com.example.JobTracker.config;

import com.example.JobTracker.auth.JwtUtil;
import com.example.JobTracker.auth.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import org.springframework.security.config.Customizer;
import java.io.IOException;
import java.util.List;

@Configuration
public class SecurityConfig {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    public SecurityConfig(JwtUtil jwtUtil, UserRepository userRepository) {
        this.jwtUtil = jwtUtil;
        this.userRepository = userRepository;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/api/jobs/**").permitAll()
                        .requestMatchers("/", "/index.html", "/static/**", "/*.ico", "/*.json", "/*.png", "/error")
                        .permitAll()
                        .anyRequest().authenticated() // all other endpoints need JWT
                )
                .addFilterBefore(new JwtFilter(jwtUtil, userRepository),
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public org.springframework.web.cors.CorsConfigurationSource corsConfigurationSource() {
        org.springframework.web.cors.CorsConfiguration configuration = new org.springframework.web.cors.CorsConfiguration();
        // Allow the frontend React app domain
        configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://127.0.0.1:3000"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setExposedHeaders(List.of("Authorization"));
        configuration.setAllowCredentials(true);

        org.springframework.web.cors.UrlBasedCorsConfigurationSource source = new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    // @Bean
    // public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    // http
    // .csrf(csrf -> csrf.disable())
    // .authorizeHttpRequests(auth -> auth.anyRequest().permitAll()); // 🚨 all open
    // return http.build();
    // }

    static class JwtFilter extends OncePerRequestFilter {
        private final JwtUtil jwtUtil;
        private final UserRepository userRepository;

        JwtFilter(JwtUtil jwtUtil, UserRepository userRepository) {
            this.jwtUtil = jwtUtil;
            this.userRepository = userRepository;
        }

        @Override
        protected void doFilterInternal(HttpServletRequest request,
                HttpServletResponse response,
                FilterChain filterChain)
                throws ServletException, IOException {
            String header = request.getHeader("Authorization");
            if (header != null && header.startsWith("Bearer ")) {
                String token = header.substring(7);
                if (jwtUtil.validateToken(token)) {
                    String username = jwtUtil.extractUsername(token);
                    var userOpt = userRepository.findByUsername(username);
                    if (userOpt.isPresent()) {
                        var auth = new UsernamePasswordAuthenticationToken(
                                username, null, List.of());
                        SecurityContextHolder.getContext().setAuthentication(auth);
                    }
                }
            }
            filterChain.doFilter(request, response);
        }
    }
}
