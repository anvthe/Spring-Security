package guddo.repository;

import guddo.domain.User;
import guddo.model.PasswordResetOtp;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PasswordResetOtpRepository extends JpaRepository<PasswordResetOtp, Long> {
    Optional<PasswordResetOtp> findByOtp(String otp);
    void deleteByUser(User user);
}