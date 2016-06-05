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
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Infrastructure;
using AspNetApiMonolithSample.EntityFramework;

namespace AspNetApiMonolithSample.Controllers
{
    [Route("[controller]")]
    public class OpenIdController : ControllerBase
    {
        private readonly SignInManager<User> _signInManager;

        private readonly ILogger _logger;

        public OpenIdController(
            SignInManager<User> signInManager,
            ILoggerFactory loggerFactory)
        {
            _signInManager = signInManager;
            _logger = loggerFactory.CreateLogger<OpenIdController>();
        }

        [HttpGet("[action]")]
        public async Task<IActionResult> Logout([FromQuery] string returnUrl = "")
        {
            await _signInManager.SignOutAsync();
            if (returnUrl.Length > 0) {
                return Redirect(returnUrl);
            }
            return new OkObjectResult("LOGGED OUT");
        }

        [HttpGet("[action]")]
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
        public async Task<IActionResult> LoginPost(LoginViewModel model,[FromQuery] string returnUrl = "")
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                if (returnUrl.Length > 0) {
                    return Redirect(returnUrl);
                }
                return new OkObjectResult("LOGGED IN");
            }
            else if (result.RequiresTwoFactor)
            {

                //return RedirectToAction(nameof(SendCode), new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                return new OkObjectResult("TWO FACTOR");
            }
            else if (result.IsLockedOut)
            {
                return new OkObjectResult("LOCKED OUT");
            }
            else if (result.IsNotAllowed)
            {
                return new OkObjectResult("NOT ALLOWED");
            }

            return new OkObjectResult("UNKNONW");
        }

        // TODO REPLICATE Authorize, Accept at least, even in same
        // https://github.com/openiddict/openiddict-core/blob/dev/src/OpenIddict.Mvc/OpenIddictController.cs
        [HttpGet("[action]"), HttpPost("[action]")]
        public virtual async Task<IActionResult> Authorize()
        {
            var services = HttpContext.RequestServices.GetRequiredService<OpenIddictServices<User, OpenIddictApplication, OpenIddictAuthorization, OpenIddictScope, OpenIddictToken>>();

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

            var application = await services.Applications.FindByIdAsync(request.ClientId);
            if (application == null)
            {
                return new ObjectResult(new OpenIdConnectMessage
                {
                    Error = OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                });

            }

            // TODO IF one of official app id's check
            if (request.ClientId == "official-docs")
            {
                // Retrieve the user data using the unique identifier.
                var user = await services.Users.GetUserAsync(User);
                if (user == null)
                {
                    return new ObjectResult(new OpenIdConnectMessage
                    {
                        Error = OpenIdConnectConstants.Errors.ServerError,
                        ErrorDescription = "An internal error has occurred"
                    });
                }

                var identity = await services.Tokens.CreateIdentityAsync(user, request.GetScopes());
                Debug.Assert(identity != null);

                // Create a new authentication ticket holding the user identity.
                var ticket = new AuthenticationTicket(
                    new ClaimsPrincipal(identity),
                    new AuthenticationProperties(),
                    services.Options.AuthenticationScheme);

                ticket.SetResources(request.GetResources());
                ticket.SetScopes(request.GetScopes());

                // Returning a SignInResult will ask ASOS to serialize the specified identity to build appropriate tokens.
                // Note: you should always make sure the identities you return contain ClaimTypes.NameIdentifier claim.
                // In this sample, the identity always contains the name identifier returned by the external provider.
                return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
            }
            return new ObjectResult("HUH?");
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