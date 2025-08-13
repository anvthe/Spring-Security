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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
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
    private final EmailSenderService emailSenderService;

    //registration
    @Transactional
    public void register(RegisterRequestDTO request, String appUrl) {

        // Check if email already exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("This email address already registered!");
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

        String verifyToken = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken(verifyToken, user);
        tokenRepository.save(verificationToken);

        String registerLink = appUrl + "/auth/verify?token=" + verifyToken;
        String subject = "Account Verification";
        String text = String.format(
                "Hello %s,\n\nPlease verify your account by clicking the link below:\n%s\n\nThis link will expire in 60 minutes.",
                user.getFirstname(), registerLink
        );

        emailSenderService.sendSimpleMessage(user.getEmail(), subject, text);
    }

    //verify
    @Transactional
    public String verifyToken(String token) {
        VerificationToken verificationToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid verification token"));

        if (verificationToken.isExpired()) {
            tokenRepository.delete(verificationToken);
            throw new IllegalStateException("Token has expired");
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

            throw new IllegalArgumentException("Invalid email or password.");
        }

        User user = userOpt.get();

        if (!user.isEnabled()) {

            throw new IllegalArgumentException("Account not verified. Please verify before logging in.");
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );
        } catch (BadCredentialsException ex) {

            throw new IllegalArgumentException("Invalid email or password.");
        } catch (DisabledException ex) {
            throw new IllegalArgumentException("Account not verified. Please verify before logging in.");
        }

        return jwtService.generateToken(user);
    }


    //update password
    @Transactional
    public void updatePassword(UpdatePasswordRequestDTO request) {

        String username = SecurityContextHolder.getContext().getAuthentication().getName();


        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found by this email"));


        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IncorrectCurrentPasswordException();
        }


        if (!request.passwordsMatch()) {
            throw new IllegalArgumentException("New password and confirm password do not match");
        }

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

        String restToken = UUID.randomUUID().toString();
        PasswordResetToken resetToken = new PasswordResetToken(restToken, user);
        pwResetTokenRepository.save(resetToken);

        String resetLink = appUrl + "/auth/reset-password?token=" + restToken;
        String subject = "Password Reset Request";
        String text = String.format(
                "Hello %s,\n\nClick the link below to reset your password:\n%s\n\nThis link will expire in 5 minutes.",
                user.getFirstname(), resetLink
        );

        emailSenderService.sendSimpleMessage(user.getEmail(), subject, text);
    }


    //rest password
    public void resetPassword(String token, ResetPasswordDTO dto) {
        PasswordResetToken resetToken = pwResetTokenRepository.findByToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid reset token"));

        if (resetToken.isExpired()) {
            throw new IllegalStateException("Token has expired");
        }

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