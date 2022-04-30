﻿using DevilStore.IdentityServer.Flow.Data;
using DevilStore.IdentityServer.Flow.Domain;
using Microsoft.EntityFrameworkCore;

namespace DevilStore.IdentityServer.Flow.Repositories
{
    public interface IUserRepository
    {
        public Task<User> SignUp(User user);
        public Task<User?> SignIn(User user);
        public Task<User?> VerifyUsername(string username);
        public Task<User?> VerifyPublicLogin(string publicLogin);
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

        public async Task<User?> SignIn(User user)
        {
            var result = await _devilDBContext.User.FirstOrDefaultAsync(x => x.username == user.username && x.password == user.password);
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
    }
}