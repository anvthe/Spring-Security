package guddo.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UpdatePasswordRequestDTO {

    @NotBlank(message = "Current password is mandatory")
    private String currentPassword;

    @NotBlank(message = "New password is mandatory")
    private String newPassword;

    @NotBlank(message = "Confirm password is mandatory")
    private String confirmPassword;

    public boolean passwordsMatch() {
        return newPassword.equals(confirmPassword);
    }
}