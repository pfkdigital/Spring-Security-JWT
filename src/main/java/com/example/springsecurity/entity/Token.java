package com.example.springsecurity.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "token")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Token {
  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Integer id;

  private String token;

  @Enumerated(EnumType.STRING)
  private TokenType tokenType;

  private boolean expired;
  private boolean revoked;

  @ManyToOne()
  @JoinColumn(name = "user_id")
  private User user;
}
