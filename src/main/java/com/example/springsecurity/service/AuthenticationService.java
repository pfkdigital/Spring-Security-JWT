package com.example.springsecurity.service;

import com.example.springsecurity.dto.AuthenticationRequest;
import com.example.springsecurity.dto.AuthenticationResponse;
import com.example.springsecurity.dto.RegisterRequest;
import com.example.springsecurity.entity.Role;
import com.example.springsecurity.entity.Token;
import com.example.springsecurity.entity.TokenType.TokenType;
import com.example.springsecurity.entity.User;
import com.example.springsecurity.repository.TokenRepository;
import com.example.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final UserRepository userRepository;
  private final TokenRepository tokenRepository;
  private final PasswordEncoder passwordEncoder;
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  public AuthenticationResponse authenticate(AuthenticationRequest registerRequest) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            registerRequest.getEmail(), registerRequest.getPassword()));
    var user =
        userRepository
            .findUserByEmail(registerRequest.getEmail())
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    var jwtToken = jwtService.generateToken(user);
    revokeAllUserToken(user);
    saveUserToken(jwtToken, user);
    return AuthenticationResponse.builder().token(jwtToken).build();
  }

  public AuthenticationResponse register(RegisterRequest registerRequest) {
    User newUser =
        User.builder()
            .firstname(registerRequest.getFirstname())
            .lastname(registerRequest.getLastname())
            .email(registerRequest.getEmail())
            .password(passwordEncoder.encode(registerRequest.getPassword()))
            .role(Role.USER)
            .build();
    User savedUser = userRepository.save(newUser);
    var jwtToken = jwtService.generateToken(newUser);
    saveUserToken(jwtToken, savedUser);
    return AuthenticationResponse.builder().token(jwtToken).build();
  }

  private void revokeAllUserToken(User user) {
    List<Token> validUserTokens = tokenRepository.findAllValidTokenByUserId(user.getId());
    if (validUserTokens.isEmpty()) return;
    validUserTokens.forEach(
        token -> {
          token.setRevoked(true);
          token.setExpired(true);
        });
    tokenRepository.saveAll(validUserTokens);
  }

  private void saveUserToken(String jwtToken, User savedUser) {
    var token =
        Token.builder()
            .token(jwtToken)
            .tokenType(TokenType.BEARER_TOKEN)
            .user(savedUser)
            .revoked(false)
            .expired(false)
            .build();

    tokenRepository.save(token);
  }
}
