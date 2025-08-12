package guddo.service;

import guddo.domain.User;
import guddo.domain.enums.Role;
import guddo.dto.*;
import guddo.exception.EmailAlreadyExistsException;
import guddo.exception.IncorrectCurrentPasswordException;
import guddo.model.PasswordResetToken;
import guddo.model.VerificationToken;
import guddo.repository.PasswordResetTokenRepository;
import guddo.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import guddo.repository.VerificationTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.UUID;


@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final VerificationTokenRepository tokenRepository;
    private final PasswordResetTokenRepository pwResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;

    //registration
    @Transactional
    public void register(RegisterRequestDTO request, String appUrl) {

        // Check if email already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("Email address already registered!");
        }

        // Build and save new user
        User user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .enabled(false)
                .build();

        userRepository.save(user);

        String token = UUID.randomUUID().toString();
        VerificationToken verificationToken = VerificationToken.builder()
                .token(token)
                .user(user)
                .expiryDate(LocalDateTime.now().plusMinutes(5))
                .build();

        tokenRepository.save(verificationToken);

        String link = appUrl + "/auth/verify?token=" + token;
        String subject = "Email Verification";
        String text = "Hello " + user.getFirstname() + ",\n\nPlease verify your account by clicking the link below:\n"
                + link + "\n\nThis link will expire in 24 hours.";

        emailService.sendSimpleMessage(user.getEmail(), subject, text);
    }

    //verify
    @Transactional
    public String verifyToken(String token) {
        VerificationToken verificationToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid verification token"));

        if (verificationToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            tokenRepository.delete(verificationToken);
            throw new RuntimeException("Token expired");
        }

        User user = verificationToken.getUser();
        user.setEnabled(true);
        userRepository.save(user);

        tokenRepository.delete(verificationToken);
        return "Account verified successfully";
    }


    //login
    @Transactional
    public String authenticate(@Valid AuthenticationRequestDTO request) {

        var userOpt = userRepository.findByEmail(request.getEmail());
        if (userOpt.isEmpty()) {

            throw new RuntimeException("Invalid email or password.");
        }

        User user = userOpt.get();

        if (!user.isEnabled()) {

            throw new RuntimeException("Account not verified. Please verify before logging in.");
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );
        } catch (BadCredentialsException ex) {

            throw new RuntimeException("Invalid email or password.");
        } catch (DisabledException ex) {
            throw new RuntimeException("Account not verified. Please verify before logging in.");
        }

        return jwtService.generateToken(user);
    }


    //update password
    @Transactional
    public void updatePassword(UpdatePasswordRequestDTO request) {
        // Get the logged-in user's email
        String username = SecurityContextHolder.getContext().getAuthentication().getName();

        // Find the user by email
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("User not found by this email"));

        // Validate current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IncorrectCurrentPasswordException();
        }

        // Validate new + confirm match
        if (!request.passwordsMatch()) {
            throw new RuntimeException("New password and confirm password do not match");
        }

        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    //forgot password
    public void requestPasswordReset(String email, String appUrl) {
        var user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("This email is not registered yet!!"));

        if (!user.isEnabled()) {
            throw new IllegalStateException("Account is not verified!");
        }

        String token = UUID.randomUUID().toString();
        PasswordResetToken resetToken = new PasswordResetToken(token, user);
        pwResetTokenRepository.save(resetToken);

        String resetLink = appUrl + "/auth/reset-password?token=" + token;
        String subject = "Password Reset Request";
        String text = String.format(
                "Hello %s,\n\nClick the link below to reset your password:\n%s\n\nThis link will expire in 5 minutes.",
                user.getFirstname(), resetLink
        );

        emailService.sendSimpleMessage(user.getEmail(), subject, text);
    }


    public void resetPassword(String token, ResetPasswordDTO dto) {
        PasswordResetToken resetToken = pwResetTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid reset token"));

        if (!dto.passwordsMatch()) {
            throw new IllegalArgumentException("New password and confirm password do not match!");
        }

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(dto.getNewPassword()));
        userRepository.save(user);

        pwResetTokenRepository.delete(resetToken);
    }


    //refresh token
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String authHeader = request.getHeader("Authorization");
        String refreshToken;
        String userEmail;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            refreshToken = authHeader.substring(7);
            userEmail = jwtService.extractUsername(refreshToken);

            if (userEmail != null) {
                var user = userRepository.findByEmail(userEmail).orElseThrow(
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