using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DevilStore.UserChatFlow.Model
{
    public class ChatMessage
    {
        public int id { get; set; }
        public int senderId { get; set; }
        public int receiveId { get; set; }
        public string subject { get; set; }
        public string message { get; set; }
        public DateTime sendTs { get; set; }
        public DateTime readTs { get; set; }
        public string chatRow { get; set; }

    }
}
