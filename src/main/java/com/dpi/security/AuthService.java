package com.dpi.security;

import com.dpi.dto.LoginRequestDto;
import com.dpi.dto.LoginResponseDto;
import com.dpi.dto.SignupRequestDto;
import com.dpi.dto.SignupResponseDto;
import com.dpi.model.User;
import com.dpi.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final AuthUtil authUtil;
    private final PasswordEncoder passwordEncoder;

    public AuthService(AuthenticationManager authenticationManager, UserRepository userRepository, AuthUtil authUtil, PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.authUtil = authUtil;
        this.passwordEncoder = passwordEncoder;
    }

    public LoginResponseDto login(LoginRequestDto loginRequestDto) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(),loginRequestDto.getPassword())
        );
        User user = (User) authentication.getPrincipal();
       String token  =  authUtil.generateAccessToken(user);
       return new LoginResponseDto(user.getId(),token);
    }

    public SignupResponseDto signUp(SignupRequestDto signupRequestDto) {
         userRepository.findByUsername(signupRequestDto.getUsername()).ifPresent(
            u->{
                throw new IllegalArgumentException("user already exit");}
         );

         User newuser = new User();
         newuser.setPassword(passwordEncoder.encode(signupRequestDto.getPassword()));
         newuser.setUsername(signupRequestDto.getUsername());

         User saveuser = userRepository.save(newuser);
         return new SignupResponseDto(saveuser.getId(),saveuser.getUsername());
    }

}
