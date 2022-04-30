using DevilStore.IdentityServer.Flow.Domain;
using DevilStore.IdentityServer.Flow.Model;
using DevilStore.IdentityServer.Flow.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DevilStore.IdentityServer.Flow.Managers
{
    public interface IUserManager
    {
        public Task<User> SignUp(UserModel user);
        public Task<User?> SignIn(UserModel user);
        public Task<User?> VerifyUsername(string username);
        public Task<User> VerifyPublicLogin(string publicLogin);

    }
    public class UserManager : IUserManager
    {
        private IUserRepository _userRepository;

        public UserManager(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }

        public async Task<User> SignUp(UserModel user)
        {
            User result;

            if (user.telegramLogin == null)
                result = await _userRepository.SignUp(new User(user.username, user.publicLogin, user.password, user.role)) ?? throw new Exception("SignUp failed");

            result = await _userRepository.SignUp(new User(user.username, user.publicLogin, user.password, user.role, user.telegramLogin)) ?? throw new Exception("SignUp failed");
            return result;
        }

        public async Task<User?> SignIn(UserModel user)
        {
            var result = await _userRepository.SignIn(new User(user.username, user.publicLogin, user.password, user.role, user.telegramLogin)) ?? throw new Exception("SignIn failed");
            return result;
        }

        public async Task<User?> VerifyUsername(string username)
        {
            var result = await _userRepository.VerifyUsername(username) ?? throw new Exception("Chouse another username");
            return result;
        }

        public async Task<User> VerifyPublicLogin(string publicLogin)
        {
            var result = await _userRepository.VerifyPublicLogin(publicLogin) ?? throw new Exception("Chouse another login");
            return result;
        }

    }
}
