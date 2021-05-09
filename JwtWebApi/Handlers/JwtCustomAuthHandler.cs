using JwtWebApi.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace JwtWebApi.Handlers
{
    public class BasicAuthenticationOptions : AuthenticationSchemeOptions
    {

    }
    public class JwtCustomAuthHandler : AuthenticationHandler<BasicAuthenticationOptions>
    {
        private readonly IAuthenticateService service;
        private readonly IConfiguration _config;
        public JwtCustomAuthHandler(IOptionsMonitor<BasicAuthenticationOptions> options, 
            ILoggerFactory logger, 
            UrlEncoder encoder, 
            ISystemClock clock,IAuthenticateService service,IConfiguration config) : base(options, logger, encoder, clock)
        {
            this.service = service;
            this._config = config;

        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
                return AuthenticateResult.Fail("Unauthorized");
            string AuthorizationHeader = Request.Headers["Authorization"];
            if (string.IsNullOrWhiteSpace(AuthorizationHeader))
                return AuthenticateResult.Fail("Unauthorized");
            if (!AuthorizationHeader.StartsWith("bearer", StringComparison.OrdinalIgnoreCase))
                return AuthenticateResult.Fail("Unauthorized");
            string Token = AuthorizationHeader.Substring("bearer".Length);
            if (string.IsNullOrEmpty(Token))
                return AuthenticateResult.Fail("Unauthorized");
            try
            {
                return ValidateToken(Token.Replace("Bearer", "").Trim().ToString());
            }
            catch(Exception ex)
            {
                return AuthenticateResult.Fail("Unauthorized");
            }
        }

        private AuthenticateResult ValidateToken(string Token)
        {
            string Key = _config.GetValue<string>("JWTSettings:Key");
            var handler = new JwtSecurityTokenHandler();
            var JsonToken = handler.ReadJwtToken(Token);
            if (JsonToken==null)
                return AuthenticateResult.Fail("Unauthorized");
            TokenValidationParameters param = new TokenValidationParameters()
            {
                //RequireExpirationTime = true,
                ValidateIssuerSigningKey=true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Key)),
                ValidateLifetime=true,
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            };

            SecurityToken securityToken;
            ClaimsPrincipal claims = handler.ValidateToken(Token, param, out securityToken);
            if(claims==null)
                return AuthenticateResult.Fail("Unauthorized");

            var Ticket = new AuthenticationTicket(claims, Scheme.Name);
            return AuthenticateResult.Success(Ticket);
        }
    }
}
