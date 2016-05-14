using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using AspNetApiMonolithSample.Mvc;
using Microsoft.AspNetCore.Authorization;
using AspNetApiMonolithSample.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;
using AspNet.Security.OpenIdConnect.Extensions;
using OpenIddict;
using OpenIddict.Models;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AspNetApiMonolithSample.Controllers
{
    [Route("[controller]")]
    public class OpenIdController : ControllerBase
    {
        private readonly UserManager<User> _userManager;

        private readonly SignInManager<User> _signInManager;

        private readonly ILogger _logger;

        /// <summary>
        /// Gets the OpenIddict services used by the controller.
        /// </summary>
        protected virtual OpenIddictServices<User, Application<int>> Services { get; }

        public OpenIdController(
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            ILoggerFactory loggerFactory)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = loggerFactory.CreateLogger<AccountController>();
        }

        [HttpGet("Login")]
        public IActionResult Login()
        {
            return new ContentResult()
            {
                Content = $@"<!DOCTYPE html>
                    <html>
                    <body>
                    <form method=""POST"">
                    <input type=""text"" name=""Email"" />   
                    <input type=""password"" name=""Password"" />
                    <button type=""submit""></button>
                    ",
                ContentType = "text/html"
            };
        }

        public class LoginViewModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        [HttpPost("Login")]
        public async Task<string> LoginPost(LoginViewModel model, string returnUrl = null)
        {
            /*
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null) {
                return "FAIL";
            }
            if (!await _signInManager.CanSignInAsync(user)) {
                return "FAIL";
            }
            if (_userManager.SupportsUserLockout && !await _userManager.IsLockedOutAsync(user)) {
                return "FAIL";
            }
            */
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                return "OK?";
                // return RedirectToLocal(returnUrl);
            }
            if (result.RequiresTwoFactor)
            {
                //return RedirectToAction(nameof(SendCode), new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                return "RequiresTwoFactor";
            }
            if (result.IsLockedOut)
            {
                // return View("Lockout");
                return "LockedOUt";
            }
            if (result.IsNotAllowed)
            {
                return "NotAllowed";
            }
            return "?";
        }

        // TODO REPLICATE Authorize, Accept at least, even in same
        // https://github.com/openiddict/openiddict-core/blob/dev/src/OpenIddict.Mvc/OpenIddictController.cs
        [HttpGet("[action]"), HttpPost("[action]")]
        public virtual async Task<IActionResult> Authorize()
        {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null)
            {
                return new ObjectResult("ERROR");
            }
            
            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                return new ObjectResult("ERROR REQUEST");
            }

            if (!User.Identities.Any(identity => identity.IsAuthenticated))
            {
                return Challenge(new AuthenticationProperties
                {
                    RedirectUri = Url.Action(nameof(Authorize), new
                    {
                        request_id = request.GetRequestId(),
                    })
                });
            }
            
            System.Console.WriteLine("FindApplicationByIdAsync, request.ClientId {0}", request.ClientId);
            var application = await Services.Applications.FindApplicationByIdAsync(request.ClientId);
            System.Console.WriteLine("FindApplicationByIdAsync!!!");
            
            if (application == null)
            {
                return new ObjectResult(new OpenIdConnectMessage
                {
                    Error = OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                });

            }
            return new ObjectResult("OK");
        }

        [Authorize(Policy = "COOKIES")]
        [HttpGet("[action]")]
        public dynamic LoggedIn([RequestUser] User loggedInUser)
        {
            return new
            {
                Id = loggedInUser.Id,
                Email = loggedInUser.Email
            };
        }
    }
}