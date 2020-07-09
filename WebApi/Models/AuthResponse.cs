using WebApi.Entities;

namespace WebApi.Models
{
    public class AuthResponse
    {
        public string AccessToken { get; set; }

        public RefreshToken RefreshToken { get; set; }
    }
}