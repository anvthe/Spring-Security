package guddo.controller;

import guddo.WebApiUrlConstants.WebApiUrlConstants;
import guddo.dto.AuthenticationRequestDTO;
import guddo.dto.RegisterRequestDTO;
import guddo.dto.UpdatePasswordRequestDTO;
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
    private final AuthenticationService service;

    //registration
    //@PreAuthorize("hasRole('ADMIN')")

    @PostMapping(WebApiUrlConstants.USER_REGISTER_API)
    public ResponseEntity<?> register(@RequestBody @Valid RegisterRequestDTO request, HttpServletRequest httpRequest) {

        String appUrl = getAppUrl(httpRequest);
        service.register(request, appUrl);

        return ResponseEntity.ok("User created successfully. Please check your email to verify your account.");
    }

    private String getAppUrl(HttpServletRequest request) {
        return request.getScheme() + "://" + request.getServerName() +
                (request.getServerPort() == 80 || request.getServerPort() == 443 ? "" : ":" + request.getServerPort());
    }


    @GetMapping(WebApiUrlConstants.USER_VERIFY_EMAIL_API)
    public ResponseEntity<?> verifyAccount(@RequestParam("token") String token) {
        try {
            String res = service.verifyToken(token);
            return ResponseEntity.ok(res);
        } catch (RuntimeException ex) {
            return ResponseEntity.badRequest().body(ex.getMessage());
        }
    }


    //login
    @PostMapping(WebApiUrlConstants.USER_LOGIN_API)
    public ResponseEntity<?> authenticate(@RequestBody @Valid AuthenticationRequestDTO request) {
        try {
            String jwt = service.authenticate(request);
            return ResponseEntity.ok(jwt);
        } catch (RuntimeException ex) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ex.getMessage());
        }
    }


    //update password
    @PutMapping(WebApiUrlConstants.USER_UPDATE_PASSWORD_API)
    public ResponseEntity<?> updatePassword(@RequestBody @Valid UpdatePasswordRequestDTO request) {

        service.updatePassword(request);
        return ResponseEntity.ok("Password updated successfully");
    }


    //refresh token
    @PostMapping(WebApiUrlConstants.USER_REFRESH_TOKEN_API)
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        service.refreshToken(request, response);
    }
}