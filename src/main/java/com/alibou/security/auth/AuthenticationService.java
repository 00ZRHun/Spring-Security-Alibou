package com.alibou.security.auth;

import ch.qos.logback.core.encoder.EchoEncoder;
import com.alibou.security.config.JwtService;
import com.alibou.security.user.Role;
import com.alibou.security.user.User;
import com.alibou.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private UserRepository repository;
    private JwtService jwtService;
    private PasswordEncoder passwordEncoder;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticateRequest request) {
        return null;
    }

}
