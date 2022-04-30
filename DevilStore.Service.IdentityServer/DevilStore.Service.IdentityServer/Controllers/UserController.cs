using DevilStore.IdentityServer.Flow.Managers;
using DevilStore.IdentityServer.Flow.Model;
using DevilStore.Service.IdentityServer.Model;
using Microsoft.AspNetCore.Mvc;

namespace DevilStore.Service.IdentityServer.Controllers
{
    [ApiController]
    [ApiVersion("1")]
    [Route("api/v{version:apiVersion}/user")]
    public class UserController : ControllerBase
    {
        private readonly IUserManager _userManager;

        public UserController(IUserManager userManager)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        }

        [HttpPost("signin")]
        public async Task<UserModel> SignIn([FromBody] UserModel user)
        {
            var result = await _userManager.SignIn(user);
            return new UserModel() 
            {
                username = result.username,
                password = result.password,
                publicLogin = result.publicLogin,
                role = result.role,
                telegramLogin = result.telegramLogin
            };
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
    }
}
