using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using SecureAuthPOC.API.Models;
using SecureAuthPOC.API.Services;

namespace SecureAuthPOC.API.Filters
{
    public class AuditLogFilter : IAsyncActionFilter
    {
        private readonly IAuthService _authService;

        public AuditLogFilter(IAuthService authService)
        {
            _authService = authService;
        }

        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            // Skip if it's not an AuthController action
            if (!context.Controller.GetType().Name.Contains("Auth"))
            {
                await next();
                return;
            }

            // Execute the action
            var resultContext = await next();

            // Log the action
            var userId = context.HttpContext.User?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            var actionName = context.ActionDescriptor.DisplayName;
            var endpoint = context.HttpContext.Request.Path;
            var ipAddress = context.HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = context.HttpContext.Request.Headers["User-Agent"].ToString();
            var success = !(resultContext.Exception != null ||
                           (resultContext.Result is ObjectResult objectResult &&
                            objectResult.StatusCode >= 400));

            await _authService.LogAuditEventAsync(new AuditLog
            {
                UserId = userId,
                Action = actionName,
                Endpoint = endpoint,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                Success = success,
                Details = $"Action {actionName} executed"
            });
        }
    }
}
