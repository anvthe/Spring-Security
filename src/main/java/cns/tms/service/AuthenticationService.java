package cns.tms.service;

import cns.tms.domain.User;
import cns.tms.domain.enums.Role;
import cns.tms.dto.AuthenticationRequestDTO;
import cns.tms.dto.RegisterRequestDTO;
import cns.tms.dto.TokenRefreshDTO;
import cns.tms.dto.UpdatePasswordRequestDTO;
import cns.tms.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public void register(RegisterRequestDTO request) {
        var user = User.builder()
                .name(request.getName())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        repository.save(user);
    }

    public String authenticate(@Valid AuthenticationRequestDTO request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(),
                request.getPassword()));
        try {
            var user = repository.findByUsername(request.getUsername()).orElseThrow();
            return jwtService.generateToken(user);
        } catch (UsernameNotFoundException usernameNotFoundException) {
            return usernameNotFoundException.getMessage();
        }
    }

    public void updatePassword(UpdatePasswordRequestDTO request) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = repository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new RuntimeException("Old password is incorrect");
        }
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        repository.save(user);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authHeader = request.getHeader("Authorization");
        String refreshToken;
        String username;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            refreshToken = authHeader.substring(7);
            username = jwtService.extractUsername(refreshToken);

            if (username != null) {
                var user = repository.findByUsername(username).orElseThrow(
                        () -> new UsernameNotFoundException("User not found")
                );

                if (jwtService.isTokenValid(refreshToken, user)) {
                    String newAccessToken = jwtService.generateToken(user);
                    TokenRefreshDTO tokenResponse = TokenRefreshDTO.builder()
                            .accessToken(newAccessToken)
                            .refreshToken(refreshToken)
                            .build();

                    response.setContentType("application/json");
                    new ObjectMapper().writeValue(response.getOutputStream(), tokenResponse);
                } else {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.getWriter().write("Invalid refresh token");
                }
            }
        } else {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Refresh token is missing");
        }
    }
}