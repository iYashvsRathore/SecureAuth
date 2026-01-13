using Microsoft.OpenApi.Any;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace SecureAuthPOC.API.Filters
{
    public class AddSwaggerHeaderFilter : IOperationFilter
    {
        public void Apply(OpenApiOperation operation, OperationFilterContext context)
        {
            if (operation.Parameters == null)
                operation.Parameters = new List<OpenApiParameter>();

            // Add X-Refresh-Token header to Logout endpoint
            if (context.MethodInfo.Name == "Logout" ||
                context.ApiDescription.RelativePath?.Contains("logout") == true)
            {
                operation.Parameters.Add(new OpenApiParameter
                {
                    Name = "X-Refresh-Token",
                    In = ParameterLocation.Header,
                    Description = "Refresh token to invalidate",
                    Required = false,
                    Schema = new OpenApiSchema
                    {
                        Type = "string"
                    }
                });
            }
        }
    }
}
