using BCrypt.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using PatrickGodAuthJWT.DTOs;
using PatrickGodAuthJWT.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace PatrickGodAuthJWT.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
  public static User user = new();

    [HttpPost("register")]
    public ActionResult<User> Register(UserDto userDto)
    {
        user.Username = userDto.Password;
        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(userDto.Password);
        return Ok(user);
    }   
    [HttpPost("login")]
    public ActionResult<User> Login(UserDto userDto)
    {
        if(user.Username != userDto.Username)
        {
            return BadRequest("User not found");
        }
        bool isAuth = BCrypt.Net.BCrypt.Verify(userDto.Password, user.PasswordHash);
        if (!isAuth)
        {
            return BadRequest("Wrong password");
        }
        
        return Ok(CreateToken(user));
    }

    private string CreateToken(User user)
    {
        List < Claim > claims =
        [
            new Claim(
                ClaimTypes.Name, user.Username
                )
,
        ];

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("hello world hello againhello world hello againhello world hello againhello world hello againhello world hello againhello world hello againhello world hello againhello world hello againhello world hello again"));
        var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
        var token = new JwtSecurityToken(
            claims:claims,
            expires:DateTime.Now.AddDays(1),
            signingCredentials : cred
            );
        var jwt = new JwtSecurityTokenHandler().WriteToken(token);
        return jwt;
    }
}
