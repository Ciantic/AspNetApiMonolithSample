using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using AspNetApiMonolithSample.Services;
using AspNetApiMonolithSample.Mvc;

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
        public async Task<IActionResult> Login([FromBody] LoginAction loginDetails)
        {
            var res = await _userService.LoginAsync(loginDetails.Email, loginDetails.PasswordPlain);
            if (res == null)
            {
                return new NotAuthorizedResult();
            }

            return new OkObjectResult(new LoginResult
            {
                Id = res.Id
            });
        }

        [HttpPost("[action]")]
        public bool Logout()
        {
            return true;
        }
    }
}