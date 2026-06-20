package com.dpi.controller;

import com.dpi.dto.LoginRequestDto;
import com.dpi.dto.LoginResponseDto;
import com.dpi.dto.SignupRequestDto;
import com.dpi.dto.SignupResponseDto;
import com.dpi.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginRequestDto loginRequestDto){
        return ResponseEntity.ok(authService.login(loginRequestDto));
    }

    @PostMapping("/signUp")
    public ResponseEntity<SignupResponseDto>signUp(@RequestBody SignupRequestDto signupRequestDto){
        return new ResponseEntity<>(authService.signUp(signupRequestDto), HttpStatus.CREATED);
    }
}
