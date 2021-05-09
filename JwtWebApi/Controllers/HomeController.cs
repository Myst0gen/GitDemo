using JwtWebApi.Models;
using JwtWebApi.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace JwtWebApi.Controllers
{
    [Route("[controller]")]
    [ApiController]
    //[ClaimsValidator("Manage Users")]
    public class HomeController : ControllerBase
    {
        private readonly IAuthenticateService _Authservice;

        public HomeController(IAuthenticateService Authservice)
        {
            _Authservice = Authservice;
        }

        [HttpPost("Login")]
        public IActionResult Login([FromBody] Users user)
        {
            ObjectResult json;
            if (user != null)
            {
                string token = _Authservice.GenerateToken(user);
                if (string.IsNullOrWhiteSpace(token) || token=="")
                {
                    json = new ObjectResult(new { status = HttpStatusCode.Unauthorized, data = "", message = "Unauthorized" });
                    return json;
                }
                else
                {
                    json = new ObjectResult(new { status = HttpStatusCode.OK, data = token, message = "Success" });
                    return json;
                }
            }
            else
            {
                json = new ObjectResult(new { status = HttpStatusCode.BadRequest, data = "", message = "Object Parameter cannot be empty" });
                return json;
            }
        }
    }
}
