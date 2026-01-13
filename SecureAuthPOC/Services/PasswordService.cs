namespace SecureAuthPOC.API.Services
{
    public class PasswordService : IPasswordService
    {
        private const int WorkFactor = 12; // BCrypt work factor

        /// <summary>
        /// Generate a Hash password with a unique salt
        /// </summary>
        /// <param name="password">Password for which the hash to be generated</param>
        /// <param name="salt">Password salt</param>
        public string HashPassword(string password, out string salt)
        {
            // Generate a unique salt for each user
            salt = BCrypt.Net.BCrypt.GenerateSalt(WorkFactor);

            // Hash password with salt
            return BCrypt.Net.BCrypt.HashPassword(password, salt);
        }

        /// <summary>
        /// Verify password against stored hash and salt
        /// </summary>
        /// <param name="password">Password to verify</param>
        /// <param name="hash">Existing password hash</param>
        /// <param name="salt">Password salt</param>
        public bool VerifyPassword(string password, string hash, string salt)
        {
            try
            {
                return BCrypt.Net.BCrypt.Verify(password, hash);
            }
            catch
            {
                // Prevent timing attacks by always taking similar time
                BCrypt.Net.BCrypt.HashPassword("dummy", salt);
                return false;
            }
        }

        /// <summary>
        /// Generate a secure random password
        /// </summary>
        /// <param name="length">Length of the password</param>
        public string GenerateSecurePassword(int length = 16)
        {
            const string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const string lowercase = "abcdefghijklmnopqrstuvwxyz";
            const string numbers = "0123456789";
            const string special = "!@#$%^&*()-_=+[]{}|;:,.<>?";

            var chars = uppercase + lowercase + numbers + special;
            var random = new Random();

            // Ensure at least one of each character type
            var password = new char[length];
            password[0] = uppercase[random.Next(uppercase.Length)];
            password[1] = lowercase[random.Next(lowercase.Length)];
            password[2] = numbers[random.Next(numbers.Length)];
            password[3] = special[random.Next(special.Length)];

            // Fill the rest
            for (int i = 4; i < length; i++)
            {
                password[i] = chars[random.Next(chars.Length)];
            }

            // Shuffle the array
            return new string(password.OrderBy(x => random.Next()).ToArray());
        }

        /// <summary>
        /// Get a basic password strength score
        /// </summary>
        /// <param name="password">Password to check the strength score</param>
        public int GetPasswordStrengthScore(string password)
        {
            int score = 0;

            if (string.IsNullOrEmpty(password)) return 0;

            // Length check
            if (password.Length >= 12) score += 2;
            if (password.Length >= 16) score += 1;

            // Character variety
            if (password.Any(char.IsUpper)) score += 1;
            if (password.Any(char.IsLower)) score += 1;
            if (password.Any(char.IsDigit)) score += 1;
            if (password.Any(c => !char.IsLetterOrDigit(c))) score += 1;

            // Entropy check (simplified)
            var uniqueChars = password.Distinct().Count();
            if (uniqueChars >= 10) score += 1;

            return score;
        }

        /// <summary>
        /// Get password feedback
        /// </summary>
        public string GetPasswordFeedback(string password)
        {
            var feedback = new List<string>();

            if (string.IsNullOrEmpty(password))
                return "Password cannot be empty";

            if (password.Length < 12)
                feedback.Add("Password should be at least 12 characters");

            if (!password.Any(char.IsUpper))
                feedback.Add("Add uppercase letters");

            if (!password.Any(char.IsLower))
                feedback.Add("Add lowercase letters");

            if (!password.Any(char.IsDigit))
                feedback.Add("Add numbers");

            if (!password.Any(c => !char.IsLetterOrDigit(c)))
                feedback.Add("Add special characters");

            return feedback.Count == 0 ? "Strong password" : string.Join(". ", feedback);
        }
    }
}
