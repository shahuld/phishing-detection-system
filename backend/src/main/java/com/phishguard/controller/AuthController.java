package com.phishguard.controller;

import com.phishguard.dto.AuthResponse;
import com.phishguard.dto.LoginRequest;
import com.phishguard.dto.RegisterRequest;
import com.phishguard.service.JwtService;
import com.phishguard.dto.ForgotPasswordRequest;
import com.phishguard.dto.ResetPasswordRequest;
import com.phishguard.dto.ResetPasswordResponse;
import com.phishguard.dto.UserProfileDto;
import com.phishguard.entity.User;
import com.phishguard.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.CrossOrigin;


@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        try {
            userService.registerUser(request);
            String jwtToken = jwtService.generateToken(userService.loadUserByUsername(request.getEmail()));
            return ResponseEntity.ok(new AuthResponse(jwtToken, "User registered successfully"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new AuthResponse(null, e.getMessage()));
        }
    }

    @PostMapping("/login")
public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        System.out.println("LOGIN ATTEMPT - Email: " + request.getEmail() + ", Password length: " + request.getPassword().length());
        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );
            String jwtToken = jwtService.generateToken((UserDetails) authentication.getPrincipal());
            return ResponseEntity.ok(new AuthResponse(jwtToken, "Login successful"));
        } catch (AuthenticationException e) {
return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new AuthResponse(null, "Invalid credentials"));
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        try {
            userService.generateResetToken(request.getEmail());
            return ResponseEntity.ok("If an account exists for this email, check your inbox (and spam) for reset instructions.");
        } catch (Exception e) {
            // Log error but generic response for security
            System.err.println("Forgot password error: " + e.getMessage());
            return ResponseEntity.ok("If an account exists for this email, check your inbox (and spam) for reset instructions.");
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ResetPasswordResponse> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        try {
            if (!request.getNewPassword().equals(request.getConfirmPassword())) {
                return ResponseEntity.badRequest().body(new ResetPasswordResponse(false, "Passwords don't match"));
            }
            userService.resetPassword(request.getToken(), request.getNewPassword());
            return ResponseEntity.ok(new ResetPasswordResponse(true, "Password reset successful"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new ResetPasswordResponse(false, e.getMessage()));
        }
    }

    @GetMapping("/profile")
    public ResponseEntity<UserProfileDto> getProfile() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userService.getUserByEmail(email);
        UserProfileDto profile = new UserProfileDto();
        profile.setName(user.getName());
        profile.setEmail(user.getEmail());
        return ResponseEntity.ok(profile);
    }
}



