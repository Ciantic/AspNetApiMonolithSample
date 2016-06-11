using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using AspNetApiMonolithSample.Mvc;
using Microsoft.AspNetCore.Authorization;
using AspNetApiMonolithSample.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System.Linq;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Authentication;
using AspNet.Security.OpenIdConnect.Extensions;
using OpenIddict;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using System.Diagnostics;
using Microsoft.Extensions.Options;
using System.Collections.Generic;
using System.Net;

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
        public async Task<IActionResult> Logout(
            [FromServices] SignInManager<User> signInManager,
            [FromServices] IOptions<OpenIddictOptions> options,
            [FromQuery] string returnUrl = "")
        {
            await signInManager.SignOutAsync();
            if (returnUrl.Length > 0) {
                return Redirect(returnUrl);
            }
            return SignOut(options.Value.AuthenticationScheme);
        }

        [HttpGet("[action]")]
        public IActionResult Login([FromServices] IOptions<BrandingHtml> brandingHtml, [FromQuery] LoginErrors error = LoginErrors.Ok)
        {
            return new ContentResult()
            {
                Content = $@"<!DOCTYPE html>
                    <html>
                    <head>
                    <script>var LOGIN_ERROR = ""{error.ToString()}"";</script>
                    {brandingHtml?.Value?.Login}
                    </head>
                    <body>
                    <form method=""POST"">
                    <input type=""text"" name=""Email"" placeholder=""EMAIL"" required />   
                    <input type=""password"" name=""Password"" placeholder=""PASSWORD"" required />
                    <input type=""checkbox"" name=""RememberMe"" />
                    <button type=""submit"">LOGIN</button>
                    ",
                ContentType = "text/html"
            };
        }

        public enum LoginErrors
        {
            Ok,
            // Authorize errors
            ResponseError,
            RequestNull,
            InvalidClient,

            // Login errors
            RedirectMissing,
            LockedOut,
            NotAllowed,
            UsernameOrPassword,

            // Accept errors
            UserNotFound,
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

        [HttpPost("Login")] // TODO: Anti forgery token
        public async Task<IActionResult> LoginPost(LoginViewModel model, [FromServices] SignInManager<User> signInManager, [FromQuery] string returnUrl = "")
        {
            var result = await signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                if (returnUrl.Length > 0) {
                    return Redirect(returnUrl);
                }
                return RedirectToAction(nameof(Login), new { error = LoginErrors.RedirectMissing });
            }
            else if (result.RequiresTwoFactor)
            {
                //return RedirectToAction(nameof(SendCode), 
                //    new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                return new OkObjectResult("TODO: TWO FACTOR");
            }
            else if (result.IsLockedOut)
            {
                return RedirectToAction(nameof(Login), new { error = LoginErrors.LockedOut });
            }
            else if (result.IsNotAllowed)
            {
                return RedirectToAction(nameof(Login), new { error = LoginErrors.NotAllowed });
            }

            return RedirectToAction(nameof(Login), new { error = LoginErrors.UsernameOrPassword });
        }

        // TODO REPLICATE Authorize, Accept at least, even in same
        // https://github.com/openiddict/openiddict-core/blob/dev/src/OpenIddict.Mvc/OpenIddictController.cs
        [HttpGet("[action]"), HttpPost("[action]")]
        public virtual async Task<IActionResult> Authorize(
            [FromServices] SignInManager<User> signInManager,
            [FromServices] OpenIddictUserManager<User> users,
            [FromServices] OpenIddictApplicationManager<OpenIddictApplication> applications,
            [FromServices] OpenIddictTokenManager<OpenIddictToken> tokens,
            [FromServices] IOptions<OpenIddictOptions> options,
            [FromServices] IOptions<List<OpenIddictApplication>> officialApplications,
            [FromServices] IOptions<BrandingHtml> brandingHtml
            )
        {
            // var services = HttpContext.RequestServices.GetRequiredService<OpenIddictServices<User, OpenIddictApplication, OpenIddictAuthorization, OpenIddictScope, OpenIddictToken>>();

            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null)
            {
                await signInManager.SignOutAsync();
                // TODO: What then? Login dialog without ability go forward?
                return RedirectToAction("Login", new { error = LoginErrors.ResponseError });
                //return Forbid();
                //return SignOut(options.Value.AuthenticationScheme);
                // TODO: Is response required to be passed here?
                // return RedirectToAction("Login", new { error = LoginErrors.ResponseError });
            }

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                return RedirectToAction(nameof(Login), new { error = LoginErrors.RequestNull });
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
                return RedirectToAction(nameof(Login), new { error = LoginErrors.InvalidClient });
            }

            // Check if the application is official (registered in settings) and accept any request by default
            if (officialApplications.Value.Where(x => x.Id == request.ClientId).Count() != 0)
            {
                return await Accept(users, applications, tokens, options);
            }

            var appName = await applications.GetDisplayNameAsync(application);
            var inputs = "";
            foreach (var item in request.Parameters)
            { 
                var key = WebUtility.HtmlEncode(item.Key);
                var value = WebUtility.HtmlEncode(item.Value);
                inputs = inputs + $@"<input type=""hidden"" name=""{key}"" value=""{value}"" />";
            }

            /* https://github.com/openiddict/openiddict-core/blob/dev/src/OpenIddict.Mvc/OpenIddictController.cs#L68
             * https://github.com/openiddict/openiddict-core/blob/dev/src/OpenIddict.Mvc/Views/Shared/Authorize.cshtml
            @foreach (var parameter in Model.Item1.Parameters) {
                <input type="hidden" name="@parameter.Key" value="@parameter.Value" />
            }

            <input formaction="@Url.Action("Accept")" class="btn btn-lg btn-success" name="Authorize" type="submit" value="Yes" />
            <input formaction="@Url.Action("Deny")" class="btn btn-lg btn-danger" name="Deny" type="submit" value="No" />
             */
            return new ContentResult()
            {
                Content = $@"<!DOCTYPE html>
                    <html>
                    <head>
                    {brandingHtml?.Value?.Authorize}
                    </head>
                    <body>
                    <form method=""POST"">
                    {inputs}
                    <button formaction=""{Url.Action(nameof(Accept))}"" type=""submit"">ACCEPT</button>
                    <button formaction=""{Url.Action(nameof(Deny))}"" type=""submit"">DENY</button>
                ",
                ContentType = "text/html"
            };
        }

        [Authorize, HttpPost("[action]")] // TODO: Anti forgery token
        public virtual async Task<IActionResult> Accept(
            [FromServices] OpenIddictUserManager<User> users,
            [FromServices] OpenIddictApplicationManager<OpenIddictApplication> applications,
            [FromServices] OpenIddictTokenManager<OpenIddictToken> tokens,
            [FromServices] IOptions<OpenIddictOptions> options)
        {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null)
            {
                // TODO: Is response required to be passed here?
                return RedirectToAction(nameof(Login), new { error = LoginErrors.ResponseError });
            }

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                return RedirectToAction(nameof(Login), new { error = LoginErrors.RequestNull });
            }

            // Retrieve the user data using the unique identifier.
            var user = await users.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction(nameof(Login), new { error = LoginErrors.UserNotFound });
            }

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = await users.CreateIdentityAsync(user, request.GetScopes());
            Debug.Assert(identity != null);

            var application = await applications.FindByIdAsync(request.ClientId);
            if (application == null)
            {
                return RedirectToAction(nameof(Login), new { error = LoginErrors.InvalidClient });
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

        [Authorize, HttpPost("[action]"), ValidateAntiForgeryToken]
        public IActionResult Deny([FromServices] IOptions<OpenIddictOptions> options)
        {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null)
            {
                return RedirectToAction(nameof(Login), new
                {
                    error = LoginErrors.ResponseError
                });
            }

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                return RedirectToAction(nameof(Login), new
                {
                    error = LoginErrors.RequestNull
                });
            }

            // Notify ASOS that the authorization grant has been denied by the resource owner.
            // Note: OpenIdConnectServerHandler will automatically take care of redirecting
            // the user agent to the client application using the appropriate response_mode.
            return Forbid(options.Value.AuthenticationScheme);
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