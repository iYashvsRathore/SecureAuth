namespace SecureAuthPOC.API.Services
{
    public interface IPasswordService
    {
        string HashPassword(string password, out string salt);
        bool VerifyPassword(string password, string hash, string salt);
        string GenerateSecurePassword(int length = 16);
        int GetPasswordStrengthScore(string password);
        string GetPasswordFeedback(string password);
    }
}
