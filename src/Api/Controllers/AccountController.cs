using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using AspNetApiMonolithSample.Mvc;
using Microsoft.AspNetCore.Authorization;
using AspNetApiMonolithSample.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System.Linq;
using System;

namespace AspNetApiMonolithSample.Controllers
{
    [Authorize]
    [Route("[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<User> _userManager;

        private readonly SignInManager<User> _signInManager;

        private readonly ILogger _logger;

        public AccountController(
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            ILoggerFactory loggerFactory)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = loggerFactory.CreateLogger<AccountController>();
        }

        public class RegisterAction
        {
            [EmailAddress]
            [Required]
            public string Email { get; set; } = "";
            
            [Required]
            [MinLength(6)]
            public string Password { get; set; } = "";
        }

        [HttpPost("[action]")]
        [AllowAnonymous]
        public async Task<bool> Register([FromBody] RegisterAction action)
        {
            var user = new User { UserName = action.Email, Email = action.Email };
            var result = await _userManager.CreateAsync(user, action.Password);
            if (result.Succeeded)
            {
                var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var callbackUrl = Url.Action("ConfirmEmail", "Account", new {
                    userId = user.Id, code = code
                });
                //await _emailSender.SendEmailAsync(model.Email, "Confirm your account",
                //    "Please confirm your account by clicking this link: <a href=\"" + callbackUrl + "\">link</a>");
                _logger.LogInformation(3, $"User created, confirmation code {code}");
                return true;
            }
            else
            {
                throw new ValidationErrorResult(result.Errors.Select(e => e.Description).ToList()).Exception();
            }
        }

        public class LoggedInResult
        {
            public string Id { get; set; }

            public string Email { get; set; } = "";

        }

        [HttpPost("[action]")]
        public LoggedInResult LoggedIn([RequestUser] User loggedInUser)
        {
            return new LoggedInResult
            {
                Id = loggedInUser.Id,
                Email = loggedInUser.Email
            };
        }

        public class ChangePasswordAction
        {
            public string CurrentPassword { get; set; } = "";

            public string NewPassword { get; set; } = "";
        }

        [HttpPost("[action]")]
        public async Task<bool> ChangePassword([FromBody] ChangePasswordAction action, [RequestUser] User user)
        {
            var res = await _userManager.ChangePasswordAsync(user, action.CurrentPassword, action.NewPassword);
            return res.Succeeded;
        }

        public class ResetPasswordAction
        {
            public string Email { get; set; } = "";
            public string Code { get; set; } = "";
            public string NewPassword { get; set; } = "";
        }

        [HttpPost("[action]")]
        [AllowAnonymous]
        public async Task<bool> ResetPassword([FromBody] ResetPasswordAction action)
        {
            var user = await _userManager.FindByNameAsync(action.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return true;
            }

            var result = await _userManager.ResetPasswordAsync(user, action.Code, action.NewPassword);
            return true;
        }

        public class ForgotPasswordAction
        {
            public string Email { get; set; } = "";
        }

        [HttpPost("[action]")]
        [AllowAnonymous]
        public async Task<bool> ForgotPassword([FromBody] ForgotPasswordAction action)
        {
            var user = await _userManager.FindByEmailAsync(action.Email);
            if (user == null || !(await _userManager.IsEmailConfirmedAsync(user)))
            {
                // Don't reveal that the user does not exist or is not confirmed
                return true;
            }
            var code = await _userManager.GeneratePasswordResetTokenAsync(user);
            // TODO: Send the code / reset link to user email

            return true;
        }

        public class ConfirmEmailAction
        {
            public string Email { get; set; } = "";
            public string Code { get; set; } = "";
        }

        [HttpPost("[action]")]
        [AllowAnonymous]
        public async Task<bool> ConfirmEmail([FromBody] ConfirmEmailAction action)
        {
            var user = await _userManager.FindByEmailAsync(action.Email);
            if (user == null)
            {
                return false;
            }

            var result = await _userManager.ConfirmEmailAsync(user, action.Code);
            return result.Succeeded;
        }

        [HttpPost("[action]")]
        public async Task<bool> LogoutAllApplications(
            [FromServices] SignInManager<User> signInManager)
        {
            await signInManager.SignOutAsync();
            return true;
        }
    }
}