using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
        private readonly IDistributedCache _distributedCache;
        public Dictionary<string, List<RefreshToken>> RefreshTokens;

        public AuthService(IDistributedCache distributedCache)
        {
            RefreshTokens = new Dictionary<string, List<RefreshToken>>();
            _distributedCache = distributedCache;
        }

        public AuthResponse Authenticate(Credentials credentials)
        {
            if (credentials.User != "user" || credentials.Password != "password")
                return null;

            var authResponse = new AuthResponse
            {
                AccessToken = GenerateAccessToken(credentials.User),
                RefreshToken = GenerateRefreshToken(credentials.User)
            };

            // Save RefreshToken in memory
            //if (!RefreshTokens.ContainsKey(credentials.User))
            //    RefreshTokens.Add(credentials.User, new List<RefreshToken>());

            //RefreshTokens[credentials.User].Add(authResponse.RefreshToken);

            // Save RefreshToken in redis cache
            SaveRefreshTokenInCache(authResponse);

            return authResponse;
        }

        private void SaveRefreshTokenInCache(AuthResponse authResponse)
        {
            DistributedCacheEntryOptions cacheOptions = new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = new TimeSpan(7, 0, 0, 0)
            };
            _distributedCache.SetString(authResponse.RefreshToken.Token, JsonSerializer.Serialize(authResponse.RefreshToken), cacheOptions);
        }

        public AuthResponse RefreshToken(string token)
        {
            //var user = RefreshTokens.Where(rt => rt.Value.Any(v => v.Token == token)).Select(t => t.Key).SingleOrDefault();
            //var refreshToken = RefreshTokens.Values.FirstOrDefault().SingleOrDefault(rt => rt.Token == token);

            var refreshToken = JsonSerializer.Deserialize<RefreshToken>(_distributedCache.GetString(token));
            var user = JsonSerializer.Deserialize<RefreshToken>(_distributedCache.GetString(token));

            if (refreshToken == null)
                return null;

            if (/*!refreshToken.IsActive ||*/ refreshToken.IsExpired)
                return null;

            var authResponse = new AuthResponse
            {
                AccessToken = GenerateAccessToken("user"),
                RefreshToken = GenerateRefreshToken("user")
            };

            //// Save RefreshToken in memory
            //if (!RefreshTokens.ContainsKey(refreshToken.Token))
            //    RefreshTokens.Add(refreshToken.Token, new List<RefreshToken>());
            //RefreshTokens[refreshToken.Token].Add(authResponse.RefreshToken);

            // Save in Redis Cache Memory
            SaveRefreshTokenInCache(authResponse);

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

        private RefreshToken GenerateRefreshToken(string user)
        {
            using (var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[64];
                rngCryptoServiceProvider.GetBytes(randomBytes);
                var TimeNow = DateTime.UtcNow;
                return new RefreshToken
                {
                    Token = Convert.ToBase64String(randomBytes),
                    User = user,
                    Expires = TimeNow.AddDays(7),
                    Created = TimeNow
                };
            }
        }
    }
}
