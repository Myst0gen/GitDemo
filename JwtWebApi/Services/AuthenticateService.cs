using JwtWebApi.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtWebApi.Services
{
    public class AuthenticateService:IAuthenticateService
    {
        private readonly AppSettings _appSettings;
        public AuthenticateService(IOptions<AppSettings> appsettings)
        {
            _appSettings = appsettings.Value;
        }
        private List<Users> lst = new List<Users>()
        {
            new Users
            {
                UserName = "Akshay",
                Password = "Admin",
                UserRole = "1"
            },
            new Users
            {
                UserName = "Rajesh",
                Password = "User",
                UserRole = "2"
            }
        };
        public string GenerateToken(Users users)
        {
            var details = lst.SingleOrDefault(x => x.UserName == users.UserName && x.Password == users.Password);
            var Urls = 
            if (details == null)
                return null;
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Key);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[] {
                    new Claim(ClaimTypes.Name, details.UserName.ToString()),
                    new Claim("Password", details.Password.ToString()),
                    new Claim(ClaimTypes.Role, details.UserRole.ToString())
                }),
                Expires = DateTime.Now.AddDays(2),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };
            var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
