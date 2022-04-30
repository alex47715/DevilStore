using DevilStore.IdentityServer.Flow.Constants;
using System.ComponentModel.DataAnnotations;

namespace DevilStore.IdentityServer.Flow.Domain
{
    public class User
    {
        [Key]
        public string username { get; set; }
        public string publicLogin { get; set; }
        public string password { get; set; }
        public Roles role { get; set; }
        public string? telegramLogin { get; set; }
        public decimal balance { get; set; } = 0;
        public bool telegramVerified { get; set; } = false;
        public DateTime? telegramLastChange { get; set; } = null;
        public string? userFingerPrints { get; set; }
        public DateTime? registrationDate { get; set; } = DateTime.Now;
        public DateTime? lastOnline { get; set; } = null;
        public string? txtStatus { get; set; } = null;
        public string? profileImage { get; set; } = null;
        public string? referal { get; set; } = null ;

        public User(string username, string publicLogin, string password, Roles role, string? telegramLogin = null)
        {
            this.username = username;
            this.publicLogin = publicLogin;
            this.password = password;
            this.role = role;
            this.telegramLogin = telegramLogin;
        }
    }
}
