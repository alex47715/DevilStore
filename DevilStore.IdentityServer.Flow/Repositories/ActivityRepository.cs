using DevilStore.IdentityServer.Flow.Constants;
using DevilStore.IdentityServer.Flow.Data;
using DevilStore.IdentityServer.Flow.Domain;

namespace DevilStore.IdentityServer.Flow.Repositories
{
    public interface IActivityRepository
    {
        public Task LogUserAction(int userId, UserActions action, bool status, DateTime dateTime);
    }
    public class ActivityRepository : IActivityRepository
    {
        private DevilDBContext _devilDBContext;

        public ActivityRepository(DevilDBContext devilDBContext)
        {
            _devilDBContext = devilDBContext ?? throw new ArgumentNullException(nameof(devilDBContext));
        }

        public async Task LogUserAction(int userId, UserActions action, bool status, DateTime dateTime)
        {
            var input = new Activity(userId, action, status, dateTime);
            _devilDBContext.Activity.Add(input);
            await _devilDBContext.SaveChangesAsync();
        }

    }
}
