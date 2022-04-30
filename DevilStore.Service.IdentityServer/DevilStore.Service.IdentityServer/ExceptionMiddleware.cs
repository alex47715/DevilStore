using DevilStore.Service.IdentityServer.Model;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Text.Json;

namespace DevilStore.Service.IdentityServer
{
    public class ExceptionMiddleware
    {
        private readonly RequestDelegate _next;

        public ExceptionMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext httpContext, ILogger<ExceptionMiddleware> logger)
        {
            try
            {
                await _next(httpContext);
            }
            catch (InvalidDataException dataException)
            {
                await HandleExceptionAsync(logger, dataException, httpContext, HttpStatusCode.BadRequest, dataException.Message);
            }
            catch (UnauthorizedAccessException invalidCredentialsException)
            {
                await HandleExceptionAsync(logger, invalidCredentialsException, httpContext, HttpStatusCode.Unauthorized, invalidCredentialsException.Message);
            }
            catch (Exception exception)
            {
                await HandleExceptionAsync(
                    logger,
                    exception,
                    httpContext,
                    HttpStatusCode.InternalServerError,
                    "Please contact technical specialist");
            }
        }

        private static Task HandleExceptionAsync(
            ILogger<ExceptionMiddleware> logger,
            Exception ex,
            HttpContext context,
            HttpStatusCode statusCode,
            string message = null)
        {
            logger.LogError("Exception occurred", ex);

            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)statusCode;

            var errorModel = new ErrorModel
            {
                StatusCode = context.Response.StatusCode,
                Message = message
            };

            var errorModelJson = JsonSerializer.Serialize(errorModel);

            return context.Response.WriteAsync(errorModelJson);
        }
    }
}
