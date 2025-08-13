package guddo.exception;

public class IncorrectCurrentPasswordException extends IllegalArgumentException {
    public IncorrectCurrentPasswordException() {
        super("Current password is incorrect");
    }
}