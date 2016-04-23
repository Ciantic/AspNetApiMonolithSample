using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using AspNetApiMonolithSample.Services;
using AspNetApiMonolithSample.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace AspNetApiMonolithSample
{
    [Route("[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly UserService _userService;

        public AccountController(UserService userService)
        {
            _userService = userService;
        }

        public class LoginAction
        {
            [Required]
            [MinLength(5)]
            [EmailAddress]
            public string Email { get; set; } = "";

            [Required]
            [MinLength(5)]
            public string PasswordPlain { get; set; } = "";
        }

        public class LoginResult
        {
            public int Id { get; set; }
        }

        [HttpPost("[action]")]
        public async Task<LoginResult> Login([FromBody] LoginAction loginDetails)
        {
            var res = await _userService.LoginAsync(loginDetails.Email, loginDetails.PasswordPlain);
            if (res == null)
            {
                throw new NotAuthorizedResult().Exception();
            }

            return new LoginResult
            {
                Id = res.Id
            };
        }
        
        public class LoggedInResult
        {
            public int Id { get; set; } = 0;
            public string Email {get; set; } = "";
        }
        
        [Authorize]
        [HttpPost("[action]")]
        public async Task<LoggedInResult> LoggedIn() {
            var loggedInUser = await _userService.LoggedInAsync(HttpContext.User);
            if (loggedInUser == null) {
                throw new NotAuthorizedResult().Exception();
            }
        
            return new LoggedInResult {
                Id = loggedInUser.Id,
                Email = loggedInUser.Email,
            };
        }

        [HttpPost("[action]")]
        public async Task<bool> Logout()
        {
            await _userService.LogoutAsync();
            return true;
        }
    }
}