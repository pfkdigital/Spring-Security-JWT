package com.example.springsecurity.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Permissions {
  ADMIN_READ("admin:read"),
  ADMIN_CREATE("admin:create"),
  ADMIN_UPDATE("admin:update"),
  ADMIN_DELETE("admin:delete"),

  MANAGER_READ("manager:read"),
  MANAGER_CREATE("manager:create"),
  MANAGER_UPDATE("manager:update"),
  MANAGER_DELETE("manager:delete");

  @Getter
  private final String permission;
};
