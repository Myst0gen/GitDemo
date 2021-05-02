using JwtWebApi.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtWebApi.Services
{
    public interface IAuthenticateService
    {
        string GenerateToken(Users user);
    }
}
