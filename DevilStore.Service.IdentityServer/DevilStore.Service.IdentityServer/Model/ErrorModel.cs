namespace DevilStore.Service.IdentityServer.Model
{
    public class ErrorModel
    {
        public ErrorModel()
        {
        }

        public ErrorModel(string message) : this()
        {
            Message = message;
        }

        public ErrorModel(int statusCode, string message) : this(message)
        {
            StatusCode = statusCode;
        }

        public int StatusCode { get; set; }

        public string Message { get; set; }
    }
}
