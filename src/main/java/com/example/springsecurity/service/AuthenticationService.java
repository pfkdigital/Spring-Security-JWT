package com.example.springsecurity.service;

import com.example.springsecurity.dto.AuthenticationRequest;
import com.example.springsecurity.dto.AuthenticationResponse;
import com.example.springsecurity.dto.RegisterRequest;
import com.example.springsecurity.entity.Role;
import com.example.springsecurity.entity.Token;
import com.example.springsecurity.entity.TokenType;
import com.example.springsecurity.entity.User;
import com.example.springsecurity.repository.TokenRepository;
import com.example.springsecurity.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityExistsException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

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
    var refreshToken = jwtService.generateRefreshToken(user);

    revokeAllUserToken(user);
    saveUserToken(jwtToken, user);
    return AuthenticationResponse.builder()
        .accessToken(jwtToken)
        .refreshToken(refreshToken)
        .build();
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
    var existingUser = userRepository.findUserByEmail(registerRequest.getEmail());
    if (existingUser.isPresent()) {
      throw new EntityExistsException("This user already exists");
    }
    User savedUser = userRepository.save(newUser);
    var jwtToken = jwtService.generateToken(newUser);
    var refreshToken = jwtService.generateRefreshToken(newUser);
    saveUserToken(jwtToken, savedUser);
    return AuthenticationResponse.builder()
        .accessToken(jwtToken)
        .refreshToken(refreshToken)
        .build();
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

  public void refresh(HttpServletRequest request, HttpServletResponse response) throws IOException {
    final String authHeader = request.getHeader("Authorization");
    final String refreshToken;
    final String userEmail;

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return;
    }
    refreshToken = authHeader.substring(7);

    userEmail = jwtService.extractUserName(refreshToken);

    if (userEmail != null) {
      User userDetails = userRepository.findUserByEmail(userEmail).orElseThrow();

      if (jwtService.isTokenValid(refreshToken, userDetails)) {
        var accessToken = jwtService.generateToken(userDetails);
        revokeAllUserToken(userDetails);
        saveUserToken(accessToken, userDetails);
        AuthenticationResponse authenticationResponse =
            AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
        new ObjectMapper().writeValue(response.getOutputStream(), authenticationResponse);
      }
    }
  }
}
