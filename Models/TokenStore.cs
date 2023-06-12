using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace JWTLogoutAsync.Net.Models
{
    public class TokenStore
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string Jwt { get; set; }
        public string ExpiryTime { get; set; }
        public bool IsLoggedOut { get; set; } = false;
    }

    public class JwtDto
    {
        public string Jwt { get; set; }
        public string ExpiryDate { get; set; }
    }
}
