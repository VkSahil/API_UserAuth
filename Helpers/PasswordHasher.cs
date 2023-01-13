using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;

namespace UserAuth.Helpers
{
    public class PasswordHasher
    {
        public static string HashPassword(string password)
        {
            string PasswordHash = BCrypt.Net.BCrypt.HashPassword(password);
            return PasswordHash;
        }

        public static bool VerifyPassword(string password, string PasswordHash)
        {
            bool verified = BCrypt.Net.BCrypt.Verify(password , PasswordHash);
            return verified;
        }
    }
}
