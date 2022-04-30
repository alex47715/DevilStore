using DevilStore.IdentityServer.Flow.Constants;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DevilStore.IdentityServer.Flow.Model
{
    public class UserModel
    {
        public string username { get; set; }
        public string publicLogin { get; set; }
        public string password { get; set; }
        public Roles role { get; set; }
        public string? telegramLogin { get; set; }
    }
}
