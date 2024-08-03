package com.example.SpringSecurity_JWT.controller;

import com.example.SpringSecurity_JWT.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
@RequiredArgsConstructor
@Tag(name = "Примеры", description = "Примеры запросов с разными правами доступа")
public class ExampleController {
    private final UserService userService;

    @GetMapping
    @Operation(summary = "Доступен только авторизованным пользователям")
    @PreAuthorize("isAuthenticated()")
    public String example() {
        return "Hello, world!";
    }


    @GetMapping("/admin")
    @Operation(summary = "Доступен только авторизованным пользователям с ролью ADMIN и SUPER_ADMIN")
    @PreAuthorize("hasRole('ADMIN') or hasRole('SUPER_ADMIN')")
    public String exampleAdmin() {
        return "Hello, admin!";
    }

    @GetMapping("/moderator")
    @Operation(summary = "Доступен только авторизованным пользователям с ролью MODERATOR и SUPER_ADMIN")
    @PreAuthorize("hasRole('MODERATOR') or hasRole('SUPER_ADMIN')")
    public String exampleModerator() {
        return "Hello, moderator!";
    }


    @GetMapping("/get-{roleEnum}")
    @Operation(summary = "Изменить роль текущего пользователя на указанную")
    public void changeRole(@PathVariable("roleEnum") String roleEnum) {
        userService.changeUserRole(roleEnum);
    }


    @GetMapping("/status")
    public String secureStatus() {
        return "Secure endpoint is working!";
    }
}