package guddo.controller;

import guddo.WebApiUrlConstants.WebApiUrlConstants;
import guddo.dto.*;
import guddo.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;


@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authService;


    //@PreAuthorize("hasRole('ADMIN')")

    //registration
    @PostMapping(WebApiUrlConstants.USER_REGISTER_API)
    public ResponseEntity<?> register(@RequestBody @Valid RegisterRequestDTO request, HttpServletRequest httpRequest) {

        String appUrl = getAppUrl(httpRequest);
        authService.register(request, appUrl);

        return ResponseEntity.ok("Account created successfully. Please check your email to verify your account.");
    }

    private String getAppUrl(HttpServletRequest request) {
        return request.getScheme() + "://" + request.getServerName() +
                (request.getServerPort() == 80 || request.getServerPort() == 443 ? "" : ":" + request.getServerPort());
    }


    //verify
    @GetMapping(WebApiUrlConstants.USER_VERIFY_EMAIL_API)
    public ResponseEntity<String> verifyAccount(@RequestParam("token") String token) {
        try {
            String result = authService.verifyToken(token);
            return ResponseEntity.ok(result);
        } catch (IllegalArgumentException | IllegalStateException ex) {

            return ResponseEntity.badRequest().body(ex.getMessage());
        } catch (Exception ex) {

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An unexpected error occurred. Please try again later.");
        }
    }


    //login
    @PostMapping(WebApiUrlConstants.USER_LOGIN_API)
    public ResponseEntity<?> authenticate(@RequestBody @Valid AuthenticationRequestDTO request) {
        try {
            String jwt = authService.authenticate(request);
            return ResponseEntity.ok(jwt);
        } catch (IllegalArgumentException | IllegalStateException ex) {

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.getMessage());
        } catch (Exception ex) {

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An unexpected error occurred. Please try again later.");
        }
    }


    //update password
    @PutMapping(WebApiUrlConstants.USER_UPDATE_PASSWORD_API)
    public ResponseEntity<?> updatePassword(@RequestBody @Valid UpdatePasswordRequestDTO request) {

        try {
            authService.updatePassword(request);
            return ResponseEntity.ok("Password updated successfully");
        } catch (IllegalArgumentException | IllegalStateException ex) {
            return ResponseEntity.badRequest().body(ex.getMessage());
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An unexpected error occurred. Please try again later.");
        }

    }

    //forgot password
    @PostMapping(WebApiUrlConstants.USER_FORGOT_PASSWORD_API)
    public ResponseEntity<?> forgotPassword(
            @RequestBody @Valid ForgotPasswordRequestDTO request, HttpServletRequest httpRequest) {
        try {
            String appUrl = httpRequest.getRequestURL()
                    .toString()
                    .replace(httpRequest.getRequestURI(), "");

            authService.requestPasswordReset(request.getEmail(), appUrl);

            return ResponseEntity.ok("Password reset link sent to your email");
        } catch (IllegalArgumentException | IllegalStateException ex) {

            return ResponseEntity.badRequest().body(ex.getMessage());
        } catch (Exception ex) {

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An unexpected error occurred. Please try again later.");
        }
    }

    //rest password
    @PostMapping((WebApiUrlConstants.USER_RESET_PASSWORD_API))
    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestBody @Valid ResetPasswordDTO request) {
        try {
            authService.resetPassword(token, request);
            return ResponseEntity.ok("Password reset successfully");
        } catch (IllegalArgumentException | IllegalStateException ex) {

            return ResponseEntity.badRequest().body(ex.getMessage());
        } catch (Exception ex) {


            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An unexpected error occurred. Please try again later.");
        }
    }


    //refresh token
    @PostMapping(WebApiUrlConstants.USER_REFRESH_TOKEN_API)
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        authService.refreshToken(request, response);
    }
}