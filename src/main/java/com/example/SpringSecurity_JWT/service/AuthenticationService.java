package com.example.SpringSecurity_JWT.service;

import com.example.SpringSecurity_JWT.dto.request.SignInRequest;
import com.example.SpringSecurity_JWT.dto.request.SignUpRequest;
import com.example.SpringSecurity_JWT.model.Role;
import com.example.SpringSecurity_JWT.model.User;
import com.example.SpringSecurity_JWT.security.util.JwtUtil;
import com.example.SpringSecurity_JWT.dto.response.JwtAuthenticationResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);

    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public JwtAuthenticationResponse signUp(SignUpRequest request) {
        var user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.ROLE_USER)
                .build();

        userService.create(user);

        var jwt = jwtUtil.generateToken(user);
        logger.debug("User signed up: {}. JWT: {}", user, jwt);
        return new JwtAuthenticationResponse(jwt);
    }

    public JwtAuthenticationResponse signIn(SignInRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getUsername(),
                request.getPassword()
        ));
        logger.debug("Authentication successful for user: {}", request.getUsername());

        var user = userService
                .userDetailsService()
                .loadUserByUsername(request.getUsername());

        var jwt = jwtUtil.generateToken(user);
        logger.debug("JWT generated for user: {}. JWT: {}", user, jwt);
        return new JwtAuthenticationResponse(jwt);
    }
}
