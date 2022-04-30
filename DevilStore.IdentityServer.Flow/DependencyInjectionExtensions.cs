using DevilStore.IdentityServer.Flow.Managers;
using DevilStore.IdentityServer.Flow.Repositories;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace DevilStore.IdentityServer.Flow
{
    public static class DependencyInjectionExtensions
    {
        public static IServiceCollection AddIndentityFlow(this IServiceCollection services, IConfiguration configuration)
        {

            services.AddTransient<IUserRepository, UserRepository>();

            services.AddTransient<IUserManager, UserManager>();

            return services;
        }
    }
}
