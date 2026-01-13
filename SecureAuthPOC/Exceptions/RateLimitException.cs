namespace SecureAuthPOC.API.Exceptions
{
    public class RateLimitException : Exception
    {
        public RateLimitException(string message) : base(message) { }
    }
}
