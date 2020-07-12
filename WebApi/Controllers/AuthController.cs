using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using WebApi.Models;
using WebApi.Services;

namespace WebApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(
            IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("authenticate")]
        public IActionResult Authenticate(Credentials credentials)
        {
            var token = _authService.Authenticate(credentials);
            setTokenCookie(token.RefreshToken.Token);
            return Ok(token);
        }

        [HttpPost("refresh")]
        public IActionResult RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var response = _authService.RefreshToken(refreshToken);

            if (response == null)
                return Unauthorized(new { message = "Invalid token" });

            setTokenCookie(response.RefreshToken.Token);

            return Ok(response);
        }

        private void setTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7)
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }

        [Authorize]
        [HttpGet]
        public IActionResult Login()
        {
            return Ok("You're logged in");
        }
    }
}
