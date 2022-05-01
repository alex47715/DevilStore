using DevilStore.IdentityServer.Flow.Constants;
using System.ComponentModel.DataAnnotations;

namespace DevilStore.IdentityServer.Flow.Domain
{
    public class Activity
    {
        [Key]
        public int actId { get; set; }
        public int userId { get; set; }
        public UserActions action { get; set; }
        public bool status { get; set; }
        public DateTime timestamp { get; set; }

        public Activity(int userId, UserActions action, bool status, DateTime timestamp)
        {
            this.userId = userId;
            this.action = action;
            this.timestamp = timestamp;
            this.status = status;
        }
    }
}
