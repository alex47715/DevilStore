using DevilStore.IdentityServer.Flow.Domain;
using Microsoft.EntityFrameworkCore;

namespace DevilStore.IdentityServer.Flow.Data
{
    public class DevilDBContext : DbContext
    {
        public DbSet<User> User { get; set; }
        public DevilDBContext(DbContextOptions<DevilDBContext> options)
            : base(options)
        {
            Database.EnsureCreated();
        }
    }
}
