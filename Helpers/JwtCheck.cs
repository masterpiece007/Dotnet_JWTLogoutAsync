using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;
using JWTLogoutAsync.Net.Models;
using LiteDB;
using LiteDB.Async;

namespace JWTLogoutAsync.Net.Helpers
{
    public class JwtCheck
    {
        private LiteDatabaseAsync db;
        private readonly string dbPath;

        public JwtCheck()
        {
            dbPath = Path.Combine(Directory.GetCurrentDirectory(), "JwtStoreAsync.db");
            db = new LiteDatabaseAsync(dbPath);
        }

        /// <summary>
        /// login: call this function at the tail end of your login method
        /// </summary>
        /// <param name="jwt">the jwt that was just generated,which is to be registered</param>
        /// <returns></returns>
        public async Task<string> LoginAsync(string jwt)
        {
            if (string.IsNullOrEmpty(jwt))
                return "empty jwt";

            var jwtExpiry = FetchJwtExpiry(jwt);
            if (string.IsNullOrEmpty(jwtExpiry))
                return "jwt expiry time not found";


            var collection = db.GetCollection<TokenStore>();

            var newJwt = new TokenStore
            {
                IsLoggedOut = false,
                Jwt = jwt,
                ExpiryTime = jwtExpiry,
                Username = FetchJwtUsername(jwt)
            };

            var rowsInserted = await collection.InsertAsync(newJwt);
            db.Dispose();
            return "Ok";

        }

        /// <summary>
        /// logout: call this function anywhere in your logout endpoint implementation
        /// </summary>
        /// <param name="jwt">jwt to be marked invalid</param>
        /// <returns></returns>
        public async Task<string> LogoutAsync(string jwt)
        {
            if (string.IsNullOrEmpty(jwt))
                return "empty jwt";
           
            var collection = db.GetCollection<TokenStore>();
            var matchingJwts = await collection.Query().Where(a => a.Jwt.ToLower() == jwt.ToLower()).ToListAsync();

            if (matchingJwts.Count > 0)
            {
                var rowsUpdated = 0;
                matchingJwts.ForEach(a =>
                {
                    a.IsLoggedOut = false;
                    var isUpdated = collection.UpdateAsync(a).GetAwaiter().GetResult();
                    _ = isUpdated ? ++rowsUpdated : rowsUpdated;
                });

                if (rowsUpdated > 0)
                {
                    db.Dispose();
                    return "OK";
                }

                db.Dispose();
                return "Failed";
            }
            db.Dispose();
            return "jwt was never logged";
           
        }

        /// <summary>
        /// logout: call this function anywhere in your logout endpoint implementation
        /// </summary>
        ///  <param name="httpContext">HttpContext that contains the incoming request</param>
        /// <returns></returns>
        public async Task<string> LogoutAsync(HttpContext httpContext)
        {
            var data = FetchJwtAndExpiry(httpContext);
            if (data == null)
                return "issue with httpContext";
           
            var collection = db.GetCollection<TokenStore>();
            var matchingJwts = await collection.Query().Where(a => a.Jwt.ToLower() == data.Jwt.ToLower())
                .ToListAsync();
            if (matchingJwts.Count > 0)
            {
                var rowsUpdated = 0;
                matchingJwts.ForEach(a =>
                {
                    a.IsLoggedOut = true;
                    var isUpdated = collection.UpdateAsync(a).GetAwaiter().GetResult();
                    _ = isUpdated ? ++rowsUpdated : rowsUpdated;
                });

                if (rowsUpdated > 0)
                {
                    db.Dispose();
                    return "OK";
                }
                db.Dispose();
                return "Failed";
            }
            db.Dispose();
            return "jwt was never logged";
        }

        internal async Task<bool> IsTokenValidAsync(string token)
        {
            if (string.IsNullOrEmpty(token))
                return false;
            var now = DateTime.Now;
            var collection = db.GetCollection<TokenStore>();
            var invalidJwts = await collection.Query()
                .Where(a =>
                    a.Jwt.ToLower() == token.ToLower() &&
                    (a.IsLoggedOut == true || now > DateTime.Parse(a.ExpiryTime))).ToListAsync();

            if (invalidJwts.Count > 0)
            {
                var rowsAffected = await collection.DeleteManyAsync(a => now > DateTime.Parse(a.ExpiryTime));
                db.Dispose();
                return false;
            }
            db.Dispose();
            return true;
        }
        public async Task<bool> HasValidSession(string username)
        {
            if (string.IsNullOrEmpty(username))
                return false;
            var now = DateTime.Now;
            var collection = db.GetCollection<TokenStore>();
            var invalidJwts = await collection.Query()
                .Where(a =>
                    a.Username.ToLower() == username.ToLower() &&
                    (a.IsLoggedOut == false || now < DateTime.Parse(a.ExpiryTime))).ToListAsync();

            if (invalidJwts.Count > 0)
            {
                var rowsAffected = await collection.DeleteManyAsync(a => now > DateTime.Parse(a.ExpiryTime));
                db.Dispose();
                return false;
            }
            db.Dispose();
            return true;
        }
        internal static JwtDto FetchJwtAndExpiry(HttpContext httpContext)
        {
            try
            {

                var jwt = ExtractJwtFromHeader(httpContext);
                if (string.IsNullOrEmpty(jwt))
                    return null;
                var handler = new JwtSecurityTokenHandler();
                var jsonToken = handler.ReadToken(jwt);
                var jwtSecurityToken = jsonToken as JwtSecurityToken;

                var expiryTime = jwtSecurityToken?.Claims.FirstOrDefault(claim => claim.Type == "exp")?.Value;

                var expiryDate = new DateTime(1970, 1, 1, 0, 0, 0, 0)
                    .AddSeconds(double.Parse(expiryTime)).ToString("MM/dd/yyyy HH:mm:ss");
                return new JwtDto { ExpiryDate = expiryDate, Jwt = jwt };
            }
            catch (Exception ex)
            {
                return null;
            }
        }
        internal static string FetchJwtExpiry(string jwt)
        {
            try
            {
                if (string.IsNullOrEmpty(jwt))
                    return null;

                var handler = new JwtSecurityTokenHandler();
                var jsonToken = handler.ReadToken(jwt);
                var tokenS = jsonToken as JwtSecurityToken;

                var expiryTime = tokenS.Claims.FirstOrDefault(claim => claim.Type == "exp")?.Value;
                return new DateTime(1970, 1, 1, 0, 0, 0, 0)
                    .AddSeconds(double.Parse(expiryTime))
                    .ToString("MM/dd/yyyy HH:mm:ss");
            }
            catch (Exception ex)
            {
                return null;
            }
        }
        internal static string FetchJwtUsername(string jwt)
        {
            try
            {
                if (string.IsNullOrEmpty(jwt))
                    return null;

                var handler = new JwtSecurityTokenHandler();
                var jsonToken = handler.ReadToken(jwt);
                var tokenS = jsonToken as JwtSecurityToken;

                var username = tokenS.Claims.FirstOrDefault(claim => claim.Type.ToLower() == "username")?.Value;
                return username;
            }
            catch (Exception ex)
            {
                return null;
            }
        }
        internal static string ExtractJwtFromHeader(HttpContext httpContext)
        {
            var authHeader = httpContext.Request.Headers[HeaderNames.Authorization].ToString();

            if (!authHeader.Contains("Bearer") && !authHeader.Contains("bearer"))
            {
                return null;
            }

            var splitHeader = authHeader.ToString().Split(' ');
            var jwt = splitHeader[1];
            return jwt;
        }

    }
}