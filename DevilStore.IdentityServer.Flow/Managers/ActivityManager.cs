using DevilStore.IdentityServer.Flow.Constants;
using DevilStore.IdentityServer.Flow.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DevilStore.IdentityServer.Flow.Managers
{
    public interface IActivityManager
    {
        public Task LogUserActivity(int userId, UserActions action, bool status, DateTime dateTime);
    }
    public class ActivityManager : IActivityManager
    {
        private IActivityRepository _activityRepository;

        public ActivityManager(IActivityRepository activityRepository)
        {
            _activityRepository = activityRepository;
        }

        public async Task LogUserActivity(int userId, UserActions action, bool status, DateTime dateTime)
        {
            await _activityRepository.LogUserAction(userId, action, status, dateTime);
        }
    }
}
