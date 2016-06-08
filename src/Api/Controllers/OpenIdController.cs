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
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using System.Collections.Generic;

namespace AspNetApiMonolithSample.Controllers
{
    [Route("[controller]")]
    public class OpenIdController : ControllerBase
    {

        private readonly ILogger _logger;

        public OpenIdController(
            ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<OpenIdController>();
        }

        [HttpGet("[action]")]
        public async Task<IActionResult> Logout([FromServices] SignInManager<User> signInManager, [FromQuery] string returnUrl = "")
        {
            await signInManager.SignOutAsync();
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
        public async Task<IActionResult> LoginPost(LoginViewModel model, [FromServices] SignInManager<User> signInManager, [FromQuery] string returnUrl = "")
        {
            var result = await signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
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
                return new BadRequestObjectResult("LOCKED OUT");
            }
            else if (result.IsNotAllowed)
            {
                return new BadRequestObjectResult("NOT ALLOWED");
            }

            return new BadRequestObjectResult("UNKNONW");
        }

        // TODO REPLICATE Authorize, Accept at least, even in same
        // https://github.com/openiddict/openiddict-core/blob/dev/src/OpenIddict.Mvc/OpenIddictController.cs
        [HttpGet("[action]"), HttpPost("[action]")]
        public virtual async Task<IActionResult> Authorize(
            [FromServices] UserManager<User> users,
            [FromServices] OpenIddictApplicationManager<OpenIddictApplication> applications,
            [FromServices] OpenIddictTokenManager<OpenIddictToken, User> tokens,
            [FromServices] IOptions<OpenIddictOptions> options,
            [FromServices] IOptions<List<OpenIddictApplication>> officialApplications
            )
        {
            // var services = HttpContext.RequestServices.GetRequiredService<OpenIddictServices<User, OpenIddictApplication, OpenIddictAuthorization, OpenIddictScope, OpenIddictToken>>();

            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null)
            {
                return new BadRequestObjectResult("ERROR");
            }

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                return new BadRequestObjectResult("ERROR REQUEST");
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

            var application = await applications.FindByIdAsync(request.ClientId);
            if (application == null)
            {
                return new BadRequestObjectResult(new OpenIdConnectMessage
                {
                    Error = OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                });

            }

            // Check if the application is official (registered in settings) and accept any request by default
            if (officialApplications.Value.Where(x => x.Id == request.ClientId).Count() != 0)
            {
                return await Accept(users, applications, tokens, options);
            }
            return new ObjectResult("HUH?");
        }

        [Authorize, HttpPost, ValidateAntiForgeryToken]
        public virtual async Task<IActionResult> Accept(
            [FromServices] UserManager<User> users,
            [FromServices] OpenIddictApplicationManager<OpenIddictApplication> applications,
            [FromServices] OpenIddictTokenManager<OpenIddictToken, User> tokens,
            [FromServices] IOptions<OpenIddictOptions> options)
        {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null)
            {
                return new BadRequestObjectResult(response);
            }

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                return new BadRequestObjectResult(new OpenIdConnectMessage
                {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Retrieve the user data using the unique identifier.
            var user = await users.GetUserAsync(User);
            if (user == null)
            {
                return new BadRequestObjectResult(new OpenIdConnectMessage
                {
                    Error = OpenIdConnectConstants.Errors.ServerError,
                    ErrorDescription = "An internal error has occurred"
                });
            }

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = await tokens.CreateIdentityAsync(user, request.GetScopes());
            Debug.Assert(identity != null);

            var application = await applications.FindByIdAsync(request.ClientId);
            if (application == null)
            {
                return new BadRequestObjectResult(new OpenIdConnectMessage
                {
                    Error = OpenIdConnectConstants.Errors.InvalidClient,
                    ErrorDescription = "Details concerning the calling client application cannot be found in the database"
                });
            }

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                options.Value.AuthenticationScheme);

            ticket.SetResources(request.GetResources());
            ticket.SetScopes(request.GetScopes());

            // Returning a SignInResult will ask ASOS to serialize the specified identity to build appropriate tokens.
            // Note: you should always make sure the identities you return contain ClaimTypes.NameIdentifier claim.
            // In this sample, the identity always contains the name identifier returned by the external provider.
            return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
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