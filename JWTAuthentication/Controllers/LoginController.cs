using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthentication.Controllers
{
    [Route("api/Login")]
    public class LoginController : Controller
    {
        private IConfiguration _config;

        public  LoginController(IConfiguration config)
        {
            _config = config;
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody]UserModel login)
        {            
            IActionResult response = Unauthorized();
            var user = AuthenticateUser(login);

            if(user != null)
            {
                var tokenString = GenerateJSONWebToken(user);
                response = Ok(new { token = tokenString });

                var securityToken = new JwtSecurityToken
                    (
                        issuer: null,
                        audience: null,
                        claims: GetClaims(),

                    );
            }

            return response;
        }

        private string GenerateJSONWebToken(UserModel userInfo)
        {            
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
              _config["Jwt:Issuer"],
              null,
              expires: DateTime.Now.AddMinutes(120),
              signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private UserModel AuthenticateUser(UserModel login)
        {
            UserModel user = login;

            //Validate the User Credentials  
            //Demo Purpose, I have Passed HardCoded User Information  
            //if (user.Username == "Jignesh")
            {
                //user = new UserModel { Username = "Jignesh Trivedi", EmailAddress = "test.btest@gmail.com" };
            }

            user = new UserModel { Username = Environment.UserName, EmailAddress = "test.btest@gmail.com" };
            return user;
        }

        private IEnumerable<Claim> GetClaims()
        {
            return null;
        }
    }
}