package guddo.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResetPasswordDTO {

    @NotBlank(message = "New password is mandatory")
    private String newPassword;

    @NotBlank(message = "Confirm password is mandatory")
    private String confirmPassword;

    public boolean passwordsMatch() {
        return newPassword.equals(confirmPassword);
    }
}
