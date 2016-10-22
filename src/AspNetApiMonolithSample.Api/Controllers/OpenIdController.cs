using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using AspNetApiMonolithSample.Api.Models;
using AspNetApiMonolithSample.Api.Mvc;
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

namespace AspNetApiMonolithSample.Api.Controllers
{
    /// <summary>
    /// OpenId specific actions, not to be used in API calls
    /// </summary>
    [Route("[controller]")]
    [ApiExplorerSettings(IgnoreApi = true)]
    public class OpenIdController : ControllerBase
    {
        private readonly ILogger _logger;
        private readonly OpenIddictApplicationManager<OpenIddictApplication> _applicationManager;
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly UiBrandingHtmlConfiguration _brandingHtml;
        private readonly IOptions<Dictionary<string, OpenIddictApplication>> _officialApplications;
        private readonly MvcJsonOptions _mvcJsonOptions;
        private readonly JwtConfiguration _jwtConfiguration;

        public OpenIdController(
            ILoggerFactory loggerFactory,
            IOptions<UiBrandingHtmlConfiguration> brandingHtml,
            IOptions<Dictionary<string, OpenIddictApplication>> officialApplications,
            IOptions<MvcJsonOptions> mvcJsonOptions,
            IOptions<JwtConfiguration> jwtConfiguration,
            OpenIddictApplicationManager<OpenIddictApplication> applicationManager,
            SignInManager<User> signInManager,
            UserManager<User> userManager)
        {
            _logger = loggerFactory.CreateLogger<OpenIdController>();
            _applicationManager = applicationManager;
            _signInManager = signInManager;
            _userManager = userManager;
            _brandingHtml = brandingHtml.Value;
            _officialApplications = officialApplications;
            _mvcJsonOptions = mvcJsonOptions.Value;
            _jwtConfiguration = jwtConfiguration.Value;
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
            UserNotFound,
            InvalidClient,
            RedirectMissing,
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
            // TODO: Anti forgery token for login
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
            }, _mvcJsonOptions.SerializerSettings);

            return new ContentResult()
            {
                Content = $@"<!DOCTYPE html>
                    <html>
                    <head>
                    <script>var OPENID_LOGIN_PAGE = {data};</script>
                    {_brandingHtml?.Login}
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
            public string RememberMe { get; set; }
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
                return RedirectToAction(nameof(ErrorController.Error), nameof(ErrorController), new { message = FatalErrors.RedirectMissing });
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null)
            {
                if (!await _userManager.IsEmailConfirmedAsync(user))
                {
                    return RedirectToLogin(LoginErrors.EmailIsNotConfirmed, returnUrl, display);
                }
            }

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe != "", lockoutOnFailure: false);
            if (result.Succeeded)
            {
                return Redirect(returnUrl);
            }
            else if (result.RequiresTwoFactor)
            {
                //return RedirectToAction(nameof(SendCode), 
                //    new { returnUrl = returnUrl, RememberMe = model.RememberMe });
                // TODO: TWO FACTOR INPUT
                // _brandingHtml?.TwoFactor
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
        [Authorize(Policy="COOKIES"), HttpGet("[action]"), HttpPost("[action]")]
        public virtual async Task<IActionResult> Authorize([RequestUser] User requestUser,
            [FromQuery] string returnUrl = "")
        {
            if (requestUser == null)
            {
                return Redirect("/OpenId/Login?ReturnUrl=" + returnUrl);
            }
            // Identity cookie that is not valid anymore (e.g. deleted user), still gets through 
            // the [Authorize] attribute by design. Check that user actually exists.
            var user = await _userManager.GetUserAsync(HttpContext.User);
            if (user == null)
            {
                await _signInManager.SignOutAsync();
                return Redirect(HttpContext.Request.GetEncodedUrl());
            }

            // Extract the authorization request from the ASP.NET environment.
            var request = HttpContext.GetOpenIdConnectRequest();

            // Retrieve the application details from the database.
            var application = await _applicationManager.FindByClientIdAsync(request.ClientId);
            if (application == null)
            {
                return RedirectToAction(nameof(ErrorController.Error), nameof(ErrorController), new { message = FatalErrors.InvalidClient });
            }

            // Check if the application is official (registered in settings) and
            // accept any request by default
            if (_officialApplications.Value.Any(x => x.Value.ClientId == request.ClientId))
            {
                return await Accept();
            }

            var appName = await _applicationManager.GetDisplayNameAsync(application);
            var inputs = "";
            var hiddenParams = new Dictionary<string, string> { { "request_id", request.RequestId } };
            foreach (var item in hiddenParams)
            {
                var key = WebUtility.HtmlEncode(item.Key);
                var value = WebUtility.HtmlEncode(item.Value);
                inputs = inputs + $@"<input type=""hidden"" name=""{key}"" value=""{value}"" />";
            }

            // TODO: Anti forgery token for Accept and Deny
            var data = JsonConvert.SerializeObject(new
            {
                Display = request.GetParameter("display"),
                Scopes = request.GetScopes().ToList(),
                FormMethod = "POST",
                FormActionAccept = Url.Action(nameof(Accept)),
                FormActionDeny = Url.Action(nameof(Deny)),
                ApplicationName = appName,
                FormData = hiddenParams
            }, _mvcJsonOptions.SerializerSettings);

            return new ContentResult()
            {
                Content = $@"<!DOCTYPE html>
                    <html>
                    <head>
                    <script>var OPENID_AUTHORIZE_PAGE = {data};</script>
                    {_brandingHtml?.Authorize}
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

            // Retrieve the profile of the logged in user.
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                await _signInManager.SignOutAsync();
                return RedirectToAction(nameof(ErrorController.Error), nameof(ErrorController), new { message = FatalErrors.UserNotFound });
            }

            // Create a new authentication ticket.
            var ticket = await CreateTicketAsync(request, user);

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

        private async Task<AuthenticationTicket> CreateTicketAsync(OpenIdConnectRequest request, User user)
        {
            // Create a new ClaimsPrincipal containing the claims that
            // will be used to create an id_token, a token or a code.
            var principal = await _signInManager.CreateUserPrincipalAsync(user);

            // Note: by default, claims are NOT automatically included in the access and identity tokens.
            // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
            // whether they should be included in access tokens, in identity tokens or in both.

            foreach (var claim in principal.Claims)
            {
                // In this sample, every claim is serialized in both the access and the identity tokens.
                // In a real world application, you'd probably want to exclude confidential claims
                // or apply a claims policy based on the scopes requested by the client application.
                claim.SetDestinations(OpenIdConnectConstants.Destinations.AccessToken,
                                      OpenIdConnectConstants.Destinations.IdentityToken);
            }

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                principal, new AuthenticationProperties(),
                OpenIdConnectServerDefaults.AuthenticationScheme);

            // Set the list of scopes granted to the client application.
            // Note: the offline_access scope must be granted
            // to allow OpenIddict to return a refresh token.
            ticket.SetScopes(new[] {
                OpenIdConnectConstants.Scopes.OpenId,
                OpenIdConnectConstants.Scopes.Email,
                OpenIdConnectConstants.Scopes.Profile,
                OpenIdConnectConstants.Scopes.OfflineAccess,
                AspNetApiMonolithSampleConstants.API_USER_SCOPE,
                OpenIddictConstants.Scopes.Roles

            }.Intersect(request.GetScopes()));

            ticket.SetResources(new string[]
            {
                _jwtConfiguration.Audience
            });

            return ticket;
        }

        private IActionResult RedirectToLogin(LoginErrors error, String returnUrl, String display = "")
        {
            return RedirectToAction(nameof(Login), new { error = error, returnUrl = returnUrl, display = display });
        }
    }
}