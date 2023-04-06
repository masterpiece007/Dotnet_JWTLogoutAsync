using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace JWTLogoutAsync.Net.Helpers
{
    
    public class JwtCheckMiddleware
    {
        private readonly RequestDelegate _next;

        public JwtCheckMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public Task Invoke(HttpContext httpContext)
        {
            var ctx = httpContext.Request.Headers[HeaderNames.Authorization];
            if (!string.IsNullOrEmpty(ctx))
            {
                //decode jwt
                var jwt = JwtCheck.ExtractJwtFromHeader(httpContext);
                if(jwt == null)
                    return _next(httpContext);

                var isValidJwt = new JwtCheck().IsTokenValidAsync(jwt).GetAwaiter().GetResult();
                if(isValidJwt)
                    return _next(httpContext);
                httpContext.Response.StatusCode = 401;
                httpContext.Response.WriteAsync("invalid token provided.").GetAwaiter().GetResult();
                return Task.CompletedTask;

            }
            return _next(httpContext);

        }

    }

    // Extension method used to add the middleware to the HTTP request pipeline.
    public static class JwtCheckMiddlewareExtensions
    {
        public static IApplicationBuilder UseJWTCheck(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<JwtCheckMiddleware>();
        }
    }
}
