using DevilStore.IdentityServer.Auth.Configurations;
using DevilStore.IdentityServer.Flow.Constants;
using DevilStore.IdentityServer.Flow.Domain;
using DevilStore.IdentityServer.Flow.Managers;
using DevilStore.IdentityServer.Flow.Model;
using DevilStore.Service.IdentityServer.Model;
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
        private readonly IActivityManager _activityManager;

        public UserController(IUserManager userManager, IActivityManager activityManager)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _activityManager = activityManager ?? throw new ArgumentNullException(nameof(activityManager));
        }

        [HttpPost("signin")]
        public async Task<ActionResult> SignIn([FromBody] SignInRequestModel user)
        {
            var result = await _userManager.SignIn(user);

            if (result.password == "invalid")
            {
                await _activityManager.LogUserActivity(result.id, UserActions.incorrectPass, true, DateTime.Now);
                return BadRequest("Invalid password");
            }
                

            await _activityManager.LogUserActivity(result.id, UserActions.successLogin, true, DateTime.Now);

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
                id = result.id,
                username = result.username,
                role = result.role,
                publicLogin = result.publicLogin,
                balance = result.balance,
                registrationDate = result.registrationDate,
                txtStatus = result.txtStatus,
                profileImage = "https://i.pinimg.com/736x/bb/f0/22/bbf022bb0f60526e32bfa4555c517c39.jpg"
            });
        }

        [HttpPost("signup")]
        public async Task<IActionResult> SignUp([FromBody] UserModel user)
        {
            var result = await _userManager.SignUp(user);
            if (result != null)
                return Ok("Sign up success");
            return BadRequest("Sign up failed");
            
        }

        [HttpGet("verify/jwt")]
        public async Task<IActionResult> JwtVerify()
        {
            return Ok(VerifyJWT(HttpContext));
        }
        [HttpGet("verify/username/{username}")]
        public async Task<IActionResult> VerifyUsername([FromRoute]string username)
        {
            var jwt = VerifyJWT(HttpContext);
            var result = await _userManager.VerifyUsername(username);
            if (result != null)
                return BadRequest("Chouse another username");
            return Ok(new
            {
                username = username
            });
        }

        [HttpGet("verify/login")]
        public async Task<IActionResult> VerifyPublicLogin([FromQuery] string publicLogin)
        {
            var jwt = VerifyJWT(HttpContext);
            var result = await _userManager.VerifyPublicLogin(publicLogin);
            return Ok(new
            {
                publicLogin = publicLogin
            });
        }

        [HttpPost("change/password")]
        public async Task<IActionResult> ChangePassword([FromBody]ChangePasswordRequestModel model)
        {
            await _userManager.ChangePassword(model.id, model.Password);
            return Ok("Password was changed");
        }

        private ClaimsIdentity GetIdentity(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimsIdentity.DefaultNameClaimType, user.id.ToString()),
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
        private Object VerifyJWT(HttpContext httpContext)
        {
            var authHeader = httpContext?.Request?.Headers?.SingleOrDefault(x => x.Key == "Authorization").Value[0];
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

            var id = GetClaim(jwt, ClaimsIdentity.DefaultNameClaimType);
            var role = GetClaim(jwt, ClaimsIdentity.DefaultRoleClaimType);

            return new
            {
                id = id,
                role = role
            };
        }
    }
}
