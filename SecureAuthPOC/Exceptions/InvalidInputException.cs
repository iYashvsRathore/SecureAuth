

using SecureAuthPOC.API.Enums;

namespace SecureAuthPOC.API.Exceptions
{
    public class InvalidInputException : Exception
    {
        public ErrorCode ErrorCode { get; }

        public InvalidInputException(ErrorCode errorCode, string message)
            : base(message)
        {
            ErrorCode = errorCode;
        }
    }
}
