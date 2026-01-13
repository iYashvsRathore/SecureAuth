using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using SecureAuthPOC.API.Exceptions;

namespace SecureAuthPOC.API.Filters.Exception
{
    public class GlobalExceptionFilter : IExceptionFilter
    {
        private readonly ILogger<GlobalExceptionFilter> _logger;

        public GlobalExceptionFilter(ILogger<GlobalExceptionFilter> logger)
        {
            _logger = logger;
        }

        public void OnException(ExceptionContext context)
        {
            _logger.LogError(context.Exception, "Unhandled exception occurred");

            ProblemDetails problem = context.Exception switch
            {
                RecordNotFoundException ex =>
                    CreateProblemDetails(
                        statusCode: StatusCodes.Status404NotFound,
                        title: "Resource not found",
                        detail: ex.Message),

                InvalidInputException ex =>
                    CreateProblemDetails(
                        statusCode: StatusCodes.Status400BadRequest,
                        title: "Invalid input provided",
                        detail: ex.Message,
                        extensions: new Dictionary<string, object?>
                        {
                            ["errorCode"] = ex.ErrorCode.ToString()
                        }),

                RateLimitException ex =>
                    CreateProblemDetails(
                        statusCode: StatusCodes.Status429TooManyRequests,
                        title: "Too many request attempts",
                        detail: ex.Message),

                ResouceLockedException ex =>
                    CreateProblemDetails(
                        statusCode: StatusCodes.Status423Locked,
                        title: "Request resource is locked",
                        detail: ex.Message),

                UnauthorizedException ex =>
                    CreateProblemDetails(
                        statusCode: StatusCodes.Status401Unauthorized,
                        title: "Unauthorized Access",
                        detail: ex.Message),

                ForbiddenException ex => 
                CreateProblemDetails(
                    statusCode: StatusCodes.Status403Forbidden,
                    title: "Forbidden",
                    detail: ex.Message ?? "You are not allowed to perform this operation."),

                _ =>
                    CreateProblemDetails(
                        statusCode: StatusCodes.Status500InternalServerError,
                        title: "Internal Server Error",
                        detail: "An unexpected error occurred")
            };

            context.Result = new ObjectResult(problem)
            {
                StatusCode = problem.Status
            };

            context.ExceptionHandled = true;
        }

        private static ProblemDetails CreateProblemDetails(
            int statusCode,
            string title,
            string detail,
            IDictionary<string, object?>? extensions = null)
        {
            var problem = new ProblemDetails
            {
                Status = statusCode,
                Title = title,
                Detail = detail,
                Type = $"https://httpstatuses.com/{statusCode}"
            };

            if (extensions != null)
            {
                foreach (var ext in extensions)
                {
                    problem.Extensions.Add(ext.Key, ext.Value);
                }
            }

            return problem;
        }
    }
}
