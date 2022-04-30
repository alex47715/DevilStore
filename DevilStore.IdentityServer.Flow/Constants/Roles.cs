using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DevilStore.IdentityServer.Flow.Constants
{
    public enum Roles
    {
        locked = 0,
        user = 1,
        seller = 2,
        varifiedSeller = 3,
        moderator = 4,
        vip = 5,
        admin = 777
    }
}
