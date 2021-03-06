using DevilStore.IdentityServer.Flow.Constants;
using DevilStore.IdentityServer.Flow.Data;
using DevilStore.IdentityServer.Flow.Domain;
using DevilStore.Service.IdentityServer.Model;
using Microsoft.EntityFrameworkCore;

namespace DevilStore.IdentityServer.Flow.Repositories
{
    public interface IUserRepository
    {
        public Task<User> SignUp(User user);
        public Task<User?> SignIn(SignInRequestModel user);
        public Task<User?> VerifyUsername(string username);
        public Task<User?> VerifyPublicLogin(string publicLogin);
        public Task<User?> ChangePassword(int id, string password);
    }
    public class UserRepository : IUserRepository
    {
        private DevilDBContext _devilDBContext;

        public UserRepository(DevilDBContext devilDBContext)
        {
            _devilDBContext = devilDBContext ?? throw new ArgumentNullException(nameof(devilDBContext));
        }

        public async Task<User> SignUp(User user)
        {
            var result = _devilDBContext.User.Add(user);
            await _devilDBContext.SaveChangesAsync();
            return result.Entity;
        }

        public async Task<User?> SignIn(SignInRequestModel user)
        {
            var result = await _devilDBContext.User.FirstOrDefaultAsync(x => x.username == user.username);

            if (result == null)
                return null;

            if (result.password != user.password)
            {
                return new User() { password = "invalid"};
            }
                
            result.lastOnline = DateTime.Now;
            _devilDBContext?.User.Update(result);
            await _devilDBContext.SaveChangesAsync();
            return result;
        }

        public async Task<User?> VerifyUsername(string username)
        {
            var result = await _devilDBContext.User.FirstOrDefaultAsync(x => x.username == username);
            return result;
        }

        public async Task<User?> VerifyPublicLogin(string publicLogin)
        {
            var result = await _devilDBContext.User.FirstOrDefaultAsync(x => x.publicLogin == publicLogin);
            return result;
        }

        public async Task<User?> ChangePassword(int id, string password)
        {
            var result = await _devilDBContext.User.FirstOrDefaultAsync(x => x.id == id);
            result.password = password;
            _devilDBContext.User.Update(result);
            await _devilDBContext.SaveChangesAsync();
            return result;
        }
    }
}
