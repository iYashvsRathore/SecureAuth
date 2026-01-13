namespace SecureAuthPOC.API.Exceptions
{
    public class ResouceLockedException : Exception
    {
        public ResouceLockedException(string message) : base(message) { }
    }
}
