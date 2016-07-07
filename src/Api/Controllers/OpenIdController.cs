using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using AspNetApiMonolithSample.Models;
using AspNetApiMonolithSample.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using OpenIddict;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AspNetApiMonolithSample.Controllers
{
    /// <summary>
    /// OpenId specific actions, not to be used in API calls
    /// </summary>
    [Route("[controller]")]
    public class OpenIdController : ControllerBase
    {
        private readonly ILogger _logger;
        private readonly OpenIddictApplicationManager<OpenIddictApplication> _applicationManager;
        private readonly SignInManager<User> _signInManager;
        private readonly OpenIddictUserManager<User> _userManager;
        private readonly IOptions<OpenIdBrandingHtml> _brandingHtml;
        private readonly IOptions<Dictionary<string, OpenIddictApplication>> _officialApplications;


        public OpenIdController(
            ILoggerFactory loggerFactory,
            IOptions<OpenIdBrandingHtml> brandingHtml,
            IOptions<Dictionary<string, OpenIddictApplication>> officialApplications,

            OpenIddictApplicationManager<OpenIddictApplication> applicationManager,
            SignInManager<User> signInManager,
            OpenIddictUserManager<User> userManager)
        {
            _logger = loggerFactory.CreateLogger<OpenIdController>();
            _applicationManager = applicationManager;
            _signInManager = signInManager;
            _userManager = userManager;
            _brandingHtml = brandingHtml;
            _officialApplications = officialApplications;
        }

        /// <summary>
        /// Logs out from all applications by removing the Identity cookies
        /// </summary>
        /// <returns></returns>
        [HttpGet("[action]")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return SignOut(OpenIdConnectServerDefaults.AuthenticationScheme);
        }

        // Fatal errors are such that are not recoverable, error must be shown, it's not possible to login
        public enum FatalErrors
        {
            ResponseError,
            UserNotFound,
            RequestNull,
            InvalidClient,
            RedirectMissing,
        }

        [HttpGet("[action]")]
        public IActionResult Error([FromQuery] FatalErrors error, [FromQuery] string display = "") {
            var data = JsonConvert.SerializeObject(new
            {
                Display = display,
                Error = error.ToString(),
            });
            return new ContentResult()
            {
                Content = $@"<!DOCTYPE html>
                    <html>
                    <head>
                    <script>var OPENID_ERROR_PAGE = {data};</script>
                    {_brandingHtml?.Value?.Error}
                    </head>
                    <body>
                    <p>ERROR: {error.ToString()}</p>
                    ",
                ContentType = "text/html; charset=utf8"
            };
        }

        // Login errors are recoverable, new login attempt may work
        public enum LoginErrors
        {
            Ok,
            LockedOut,
            NotAllowed,
            UsernameOrPassword,
            EmailIsNotConfirmed,
        }

        [HttpGet("[action]")]
        public IActionResult Login(
            [FromQuery] LoginErrors error = LoginErrors.Ok,
            [FromQuery] string returnUrl = "",
            [FromQuery] string display = "")
        {
            var data = JsonConvert.SerializeObject(new
            {
                Display = display,
                Error = error.ToString(),
                FormMethod = "POST",
                FormAction = Url.Action(nameof(LoginPost), new
                {
                    returnUrl = returnUrl,
                    display = display
                }),
                FormData = new
                {
                    Email = "",
                    Password = "",
                    RememberMe = "",
                }
            });
            return new ContentResult()
            {
                Content = $@"<!DOCTYPE html>
                    <html>
                    <head>
                    <script>var OPENID_LOGIN_PAGE = {data};</script>
                    {_brandingHtml?.Value?.Login}
                    </head>
                    <body>
                    <form action=""{Url.Action(nameof(LoginPost), new { returnUrl = returnUrl, display = display })}"" method=""POST"">
                    <input type=""email"" name=""Email"" placeholder=""EMAIL"" required />
                    <input type=""password"" name=""Password"" placeholder=""PASSWORD"" required />
                    <input type=""checkbox"" name=""RememberMe"" value=""1"" title=""REMEMBER_ME"" />
                    <button type=""submit"">LOGIN</button>
                    ",
                ContentType = "text/html; charset=utf8"
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

        /// <summary>
        /// Handle login 
        /// </summary>
        [HttpPost("Login")] // TODO: Anti forgery token
        public async Task<IActionResult> LoginPost(
            [FromForm] LoginViewModel model,
            [FromQuery] string returnUrl = "",
            [FromQuery] string display = "")
        {
            if (returnUrl.Length == 0)
            {
                return RedirectToFatal(FatalErrors.RedirectMissing, display);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null)
            {
                if (!await _userManager.IsEmailConfirmedAsync(user))
                {
                    return RedirectToLogin(LoginErrors.EmailIsNotConfirmed, returnUrl, display);
                }
            }

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                return Redirect(returnUrl);
            }
            else if (result.RequiresTwoFactor)
            {
                //return RedirectToAction(nameof(SendCode), 
                //    new { returnUrl = returnUrl, RememberMe = model.RememberMe });
                // TODO: TWO FACTOR INPUT
                return new OkObjectResult("TODO: TWO FACTOR");
            }
            else if (result.IsLockedOut)
            {
                return RedirectToLogin(LoginErrors.LockedOut, returnUrl, display);
            }
            else if (result.IsNotAllowed)
            {
                return RedirectToLogin(LoginErrors.NotAllowed, returnUrl, display);
            }
            return RedirectToLogin(LoginErrors.UsernameOrPassword, returnUrl, display);
        }

        /// <summary>
        /// Authorize OpenId request, shows the accept or deny dialog if applicable
        /// </summary>
        [Authorize(Policy = "COOKIES"), HttpGet("[action]"), HttpPost("[action]")]
        public virtual async Task<IActionResult> Authorize(
            [FromQuery] string state = "",
            [FromQuery] string display = "",
            [FromQuery] string client_id = "",
            [FromQuery] string prompt = ""
            )
        {
            // Extract the authorization request from the ASP.NET environment.
            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                var response = HttpContext.GetOpenIdConnectResponse();
                if (response.Error == "server_error")
                {
                    await _signInManager.SignOutAsync();
                    return Redirect(HttpContext.Request.GetEncodedUrl());
                }
                return RedirectToFatal(FatalErrors.RequestNull, display);
            }

            // Retrieve the application details from the database.
            var application = await _applicationManager.FindByClientIdAsync(request.ClientId);
            if (application == null)
            {
                RedirectToFatal(FatalErrors.InvalidClient, display);
            }

            if (!User.Identities.Any(identity => identity.IsAuthenticated))
            {
                if (prompt == "none")
                {
                    return Redirect(QueryHelpers.AddQueryString(application.RedirectUri, new Dictionary<string, string>()
                    {
                        { "error", "login_required" },
                        { "state", state }
                    }));
                }
                return RedirectToLogin(LoginErrors.Ok, Request.GetEncodedUrl(), display);
            }

            // Check if the application is official (registered in settings) and
            // accept any request by default
            if (_officialApplications.Value.Any(x => x.Value.ClientId == request.ClientId))
            {
                return await Accept();
            }

            var appName = await _applicationManager.GetDisplayNameAsync(application);
            var inputs = "";
            foreach (var item in request.Parameters)
            {
                var key = WebUtility.HtmlEncode(item.Key);
                var value = WebUtility.HtmlEncode(item.Value);
                inputs = inputs + $@"<input type=""hidden"" name=""{key}"" value=""{value}"" />";
            }

            // TODO: Anti forgery token for Accept and Deny
            var data = JsonConvert.SerializeObject(new
            {
                Display = request.Display,
                FormMethod = "POST",
                FormActionAccept = Url.Action(nameof(Accept)),
                FormActionDeny = Url.Action(nameof(Deny)),
                ApplicationName = appName,
                FormData = request.Parameters
            });

            return new ContentResult()
            {
                Content = $@"<!DOCTYPE html>
                    <html>
                    <head>
                    <script>var OPENID_AUTHORIZE_PAGE = {data};</script>
                    {_brandingHtml?.Value?.Authorize}
                    </head>
                    <body>
                    <form enctype=""application/x-www-form-urlencoded"" method=""POST"">
                    {inputs}
                    <div>{WebUtility.HtmlEncode(appName)}</div>
                    <button formaction=""{Url.Action(nameof(Accept))}"" type=""submit"" />ACCEPT</button>
                    <button formaction=""{Url.Action(nameof(Deny))}"" type=""submit"">DENY</button>
                ",
                ContentType = "text/html; charset=utf8"
            };
        }

        /// <summary>
        /// Accept the application request
        /// </summary>
        [Authorize(Policy = "COOKIES"), HttpPost("Authorize/[action]")] // TODO: Anti forgery token
        public virtual async Task<IActionResult> Accept()
        {
            // Extract the authorization request from the ASP.NET environment.
            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                return RedirectToFatal(FatalErrors.RequestNull);
            }

            // Retrieve the profile of the logged in user.
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                RedirectToFatal(FatalErrors.UserNotFound);
            }

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = await _userManager.CreateIdentityAsync(user, request.GetScopes());

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            ticket.SetResources(request.GetResources());
            ticket.SetScopes(request.GetScopes());

            // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
            return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
        }

        /// <summary>
        /// Deny the application request
        /// </summary>
        [Authorize(Policy = "COOKIES"), HttpPost("Authorize/[action]")] // TODO: Anti forgery token
        public IActionResult Deny()
        {
            // Notify OpenIddict that the authorization grant has been denied by the resource owner
            // to redirect the user agent to the client application using the appropriate response_mode.
            return Forbid(OpenIdConnectServerDefaults.AuthenticationScheme);
        }

        // TODO: Change to POST or remove
        [HttpGet("[action]")]
        [Authorize(Policy = "COOKIES")]
        public dynamic LoggedIn([RequestUser] User loggedInUser)
        {
            return new
            {
                Id = loggedInUser.Id,
                Email = loggedInUser.Email
            };
        }

        private IActionResult RedirectToFatal(FatalErrors error, string display = "")
        {
            return RedirectToAction(nameof(Error), new { error = error, display = display });
        }

        private IActionResult RedirectToLogin(LoginErrors error, String returnUrl, String display = "")
        {
            return RedirectToAction(nameof(Login), new { error = error, returnUrl = returnUrl, display = display });
        }
    }
}