package com.example.SpringSecurity_JWT.service;

import com.example.SpringSecurity_JWT.model.Role;
import com.example.SpringSecurity_JWT.model.User;
import com.example.SpringSecurity_JWT.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;


@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_TIME_DURATION = 30;
    public User save(User user) {
        return userRepository.save(user);
    }

    public User create(User user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new RuntimeException("Пользователь с таким именем уже существует");
        }
        if (userRepository.existsByEmail(user.getEmail())) {
            throw new RuntimeException("Пользователь с таким email уже существует");
        }
        return save(user);
    }
    public User getByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Пользователь не найден"));

    }
    public UserDetailsService userDetailsService() {
        return this::getByUsername;
    }

    public User getCurrentUser() {
        var username = SecurityContextHolder.getContext().getAuthentication().getName();
        return getByUsername(username);
    }

    public void changeUserRole(String roleEnum) {
        Role newRole;
        try {
            newRole = Role.valueOf(roleEnum);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid role: " + roleEnum);
        }

        User user = getCurrentUser();
        if (user == null) {
            throw new RuntimeException("No user is currently authenticated");
        }

        user.setRole(newRole);
        userRepository.save(user);
    }

    public void handleFailedLogin(User user) {
        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            if (Duration.between(user.getLastFailedLoginAttempt(), LocalDateTime.now()).toMinutes() > LOCK_TIME_DURATION) {
                user.setFailedLoginAttempts(0);
            } else {
                throw new RuntimeException("Account is locked. Please try again later.");
            }
        }

        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
        user.setLastFailedLoginAttempt(LocalDateTime.now());
        userRepository.save(user);

        checkRemainingAttempts(user);
    }

    private void checkRemainingAttempts(User user) {
        int remainingAttempts = MAX_FAILED_ATTEMPTS - user.getFailedLoginAttempts();
        if (remainingAttempts > 0) {
            throw new RuntimeException("Invalid login attempt. You have " + remainingAttempts + " attempt(s) left.");
        } else {
            throw new RuntimeException("Invalid login attempt. Your account is now locked.");
        }
    }

    public void resetFailedAttempts(User user) {
        user.setFailedLoginAttempts(0);
        userRepository.save(user);
    }


}