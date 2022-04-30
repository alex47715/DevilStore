using DevilStore.IdentityServer.Auth.Configurations;
using DevilStore.IdentityServer.Flow.Domain;
using DevilStore.IdentityServer.Flow.Managers;
using DevilStore.IdentityServer.Flow.Model;
using DevilStore.Service.IdentityServer.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace DevilStore.Service.IdentityServer.Controllers
{
    [ApiController]
    [ApiVersion("1")]
    [Route("api/v{version:apiVersion}/identity")]
    public class UserController : ControllerBase
    {
        private readonly IUserManager _userManager;

        public UserController(IUserManager userManager)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        }

        [HttpPost("signin")]
        public async Task<ActionResult> SignIn([FromBody] SignInRequestModel user)
        {
            var result = await _userManager.SignIn(user);

            var identity = GetIdentity(result);
            var now = DateTime.UtcNow;

            var jwt = new JwtSecurityToken(
                    issuer: AuthOptions.ISSUER,
                    audience: AuthOptions.AUDIENCE,
                    notBefore: now,
                    claims: identity.Claims,
                    expires: now.Add(TimeSpan.FromMinutes(AuthOptions.LIFETIME)),
                    signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            return Ok(new
            {
                jwt = encodedJwt,
                username = result.username,
                role = result.role
            });
        }

        [HttpPost("signup")]
        public async Task<UserModel> SignUp([FromBody] UserModel user)
        {
            var result = await _userManager.SignUp(user);
            return new UserModel()
            {
                username = result.username,
                password = result.password,
                publicLogin = result.publicLogin,
                role = result.role,
                telegramLogin = result.telegramLogin
            };
        }

        [HttpGet("verify/jwt")]
        public async Task<IActionResult> JwtVerify()
        {
            var authHeader = HttpContext?.Request?.Headers?.SingleOrDefault(x => x.Key == "Authorization").Value[0];
            var jwt = authHeader.Substring(authHeader.IndexOf(' ') + 1);
            var validationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                // строка, представляющая издателя
                ValidIssuer = AuthOptions.ISSUER,

                // будет ли валидироваться потребитель токена
                ValidateAudience = true,
                // установка потребителя токена
                ValidAudience = AuthOptions.AUDIENCE,
                // будет ли валидироваться время существования
                ValidateLifetime = true,

                // установка ключа безопасности
                IssuerSigningKey = AuthOptions.GetSymmetricSecurityKey(),
                // валидация ключа безопасности
                ValidateIssuerSigningKey = true,

            };

            var handler = new JwtSecurityTokenHandler();

            var principal = handler.ValidateToken(jwt, validationParameters, out var validToken);
            JwtSecurityToken validJwt = validToken as JwtSecurityToken;

            if (validJwt == null)
            {
                throw new UnauthorizedAccessException("Invalid JWT");
            }

            if (!validJwt.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.Ordinal))
            {
                throw new UnauthorizedAccessException("Invalid JWT");
            }

            var username = GetClaim(jwt, ClaimsIdentity.DefaultNameClaimType);
            var role = GetClaim(jwt, ClaimsIdentity.DefaultRoleClaimType);

            return Ok(new
            {
                username = username,
                role = role
            });
        }

        [HttpGet("verify/username")]
        public async Task<IActionResult> VerifyUsername([FromQuery]string username)
        {
            var result = await _userManager.VerifyUsername(username);
            return Ok(new
            {
                username = username
            });
        }

        [HttpGet("verify/login")]
        public async Task<IActionResult> VerifyPublicLogin([FromQuery] string publicLogin)
        {
            var result = await _userManager.VerifyPublicLogin(publicLogin);
            return Ok(new
            {
                publicLogin = publicLogin
            });
        }

        private ClaimsIdentity GetIdentity(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimsIdentity.DefaultNameClaimType, user.username),
                new Claim(ClaimsIdentity.DefaultRoleClaimType, user.role.ToString())
            };
            ClaimsIdentity claimsIdentity =
            new ClaimsIdentity(claims, "Authorization", ClaimsIdentity.DefaultNameClaimType,
                ClaimsIdentity.DefaultRoleClaimType);
            return claimsIdentity;
        }

        private string GetClaim(string token, string claimType)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
            var stringClaimValue = securityToken.Claims.First(claim => claim.Type == claimType).Value;
            return stringClaimValue;
        }
    }
}
