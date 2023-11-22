package com.example.springsecurity;

import com.example.springsecurity.dto.RegisterRequest;
import com.example.springsecurity.entity.Role;
import com.example.springsecurity.service.AuthenticationService;
import lombok.Builder;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringSecurityApplication {

  public static void main(String[] args) {
    SpringApplication.run(SpringSecurityApplication.class, args);
  }

  @Bean
  public CommandLineRunner commandLineRunner(AuthenticationService authenticationService) {
    return args -> {
      var admin =
          RegisterRequest.builder()
              .firstname("Admin")
              .lastname("Admin")
              .email("admin@test.com")
              .password("123")
              .role(Role.ADMIN)
              .build();

      var manager =
          RegisterRequest.builder()
              .firstname("Manager")
              .lastname("Manager")
              .email("manager@test.com")
              .password("123")
              .role(Role.MANAGER)
              .build();
      System.out.println(
          "Admin Token: " + authenticationService.register(admin).getAccessToken());
      System.out.println(
          "Manager Token: " + authenticationService.register(manager).getAccessToken());
    };
  }
}
