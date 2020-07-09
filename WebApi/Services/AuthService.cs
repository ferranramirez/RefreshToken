using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApi.Entities;
using WebApi.Models;

namespace WebApi.Services
{
    public interface IAuthService
    {
        AuthResponse Authenticate(Credentials credentials);
        AuthResponse RefreshToken(string token);
    }

    public class AuthService : IAuthService
    {
        public Dictionary<string, List<RefreshToken>> RefreshTokens;

        public AuthService()
        {
            RefreshTokens = new Dictionary<string, List<RefreshToken>>();
        }

        public AuthResponse Authenticate(Credentials credentials)
        {
            if (credentials.User != "user" || credentials.Password != "password")
                return null;

            var authResponse = new AuthResponse
            {
                AccessToken = GenerateAccessToken(credentials.User),
                RefreshToken = GenerateRefreshToken()
            };

            // Save RefreshToken in memory
            if (!RefreshTokens.ContainsKey(credentials.User))
                RefreshTokens.Add(credentials.User, new List<RefreshToken>());

            RefreshTokens[credentials.User].Add(authResponse.RefreshToken);

            return authResponse;
        }

        public AuthResponse RefreshToken(string token)
        {
            var user = RefreshTokens.Where(rt => rt.Value.Any(v => v.Token == token)).Select(t => t.Key).SingleOrDefault();

            var refreshToken = RefreshTokens.Values.FirstOrDefault().Where(rt => rt.Token == token).SingleOrDefault();

            if (refreshToken == null)
                return null;

            if (/*!refreshToken.IsActive ||*/ refreshToken.IsExpired)
                return null;

            var authResponse = new AuthResponse
            {
                AccessToken = GenerateAccessToken("user"),
                RefreshToken = GenerateRefreshToken()
            };

            // Save RefreshToken in memory
            if (!RefreshTokens.ContainsKey(user))
                RefreshTokens.Add(user, new List<RefreshToken>());

            RefreshTokens[user].Add(authResponse.RefreshToken);

            return authResponse;
        }

        private string GenerateAccessToken(string user)
        {
            var identity = new ClaimsIdentity(IdentityConstants.ApplicationScheme);
            identity.AddClaim(new Claim(ClaimTypes.Name, user));

            byte[] secretKey = Encoding.ASCII.GetBytes("The secret key to generate my JWT access token");

            var jwtSecurityToken = new JwtSecurityToken(
                notBefore: DateTime.UtcNow,
                claims: identity.Claims,
                expires: DateTime.UtcNow.AddSeconds(30),
                signingCredentials: new SigningCredentials(
                    new SymmetricSecurityKey(secretKey), SecurityAlgorithms.HmacSha256)
                );

            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        }

        private RefreshToken GenerateRefreshToken()
        {
            using (var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[64];
                rngCryptoServiceProvider.GetBytes(randomBytes);
                return new RefreshToken
                {
                    Token = Convert.ToBase64String(randomBytes),
                    Expires = DateTime.UtcNow.AddDays(7),
                    Created = DateTime.UtcNow
                };
            }
        }
    }
}
