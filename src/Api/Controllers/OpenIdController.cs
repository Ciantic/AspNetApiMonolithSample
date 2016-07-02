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
using Newtonsoft.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using System;
using Microsoft.AspNetCore.WebUtilities;

namespace AspNetApiMonolithSample.Controllers
{
    /// <summary>
    /// OpenId specific actions, not to be used in API calls
    /// </summary>
    [Route("[controller]")]
    public class OpenIdController : ControllerBase
    {
        private readonly ILogger _logger;

        public OpenIdController(
            ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<OpenIdController>();
        }

        /// <summary>
        /// Logs out from all applications by removing the cookies, this method is not used by OpenId specification
        /// 
        /// 
        /// </summary>
        /// <param name="signInManager"></param>
        /// <param name="options"></param>
        /// <param name="clientId">Client ID to log out, leave this empty if you want to log out from all applications</param>
        /// <param name="returnUrl"></param>
        /// <returns></returns>
        [HttpGet("[action]")]
        public async Task<IActionResult> Logout(
            [FromServices] SignInManager<User> signInManager,
            [FromServices] OpenIddictApplicationManager<OpenIddictApplication> applications,
            [FromServices] IOptions<OpenIddictOptions> options,
            [FromQuery] string post_logout_redirect_uri = "",
            [FromQuery] string id_token_hint = "",
            [FromQuery] string state = "")
        {
            var client = await applications.FindByLogoutRedirectUri(post_logout_redirect_uri);
            if (client == null)
            {
                return new BadRequestResult();
            }

            await RemoveAndLogoutClient(HttpContext, client.Id, signInManager);
            return Redirect(post_logout_redirect_uri);    
        }

        public enum LoginErrors
        {
            Ok,
            // Fatal errors are such that one should hide the login dialog
            FatalResponseError,
            FatalUserNotFound,
            FatalRequestNull,
            FatalInvalidClient,
            FatalRedirectMissing,

            // Login errors are recoverable, new login attempt may work
            LockedOut,
            NotAllowed,
            UsernameOrPassword,
            EmailIsNotConfirmed,

        }

        [HttpGet("[action]")]
        public IActionResult Login([FromServices] IOptions<BrandingHtml> brandingHtml, [FromQuery] LoginErrors error = LoginErrors.Ok, [FromQuery] string ReturnUrl = "")
        {
            var data = JsonConvert.SerializeObject(new
            {
                Error = error.ToString(),
                FormMethod = "POST",
                FormAction = Url.Action(nameof(LoginPost), new { ReturnUrl = ReturnUrl }),
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
                    {brandingHtml?.Value?.Login}
                    </head>
                    <body>
                    <form action=""{Url.Action(nameof(LoginPost), new { ReturnUrl = ReturnUrl })}"" method=""POST"">
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

        [HttpPost("Login")] // TODO: Anti forgery token
        public async Task<IActionResult> LoginPost(
            [FromForm] LoginViewModel model,
            [FromServices] UserManager<User> userManager,
            [FromServices] SignInManager<User> signInManager, 
            [FromQuery] string ReturnUrl = "")
        {
            if (ReturnUrl.Length == 0)
            {
                return RedirectToAction(nameof(Login), new { error = LoginErrors.FatalRedirectMissing });
            }

            var user = await userManager.FindByEmailAsync(model.Email);
            if (user != null)
            {
                if (!await userManager.IsEmailConfirmedAsync(user))
                {
                    return RedirectToAction(nameof(Login), new { error = LoginErrors.EmailIsNotConfirmed, ReturnUrl = ReturnUrl });
                }
            }

            var result = await signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
            if (result.Succeeded)
            { 
                return Redirect(ReturnUrl);
            }
            else if (result.RequiresTwoFactor)
            {
                //return RedirectToAction(nameof(SendCode), 
                //    new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                // TODO: TWO FACTOR INPUT
                return new OkObjectResult("TODO: TWO FACTOR");
            }
            else if (result.IsLockedOut)
            {
                return RedirectToAction(nameof(Login), new { error = LoginErrors.LockedOut, ReturnUrl = ReturnUrl });
            }
            else if (result.IsNotAllowed)
            {
                return RedirectToAction(nameof(Login), new { error = LoginErrors.NotAllowed, ReturnUrl = ReturnUrl });
            }
            Console.WriteLine("Username or PASSWORD: redirect to ", LoginErrors.UsernameOrPassword);
            return RedirectToAction(nameof(Login), new { error = LoginErrors.UsernameOrPassword, ReturnUrl = ReturnUrl });
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
            [FromServices] IOptions<BrandingHtml> brandingHtml,
            [FromQuery(Name = "client_id")] string DirtyClientId = "",
            [FromQuery(Name = "prompt")] string DirtyPrompt = ""
            )
        {

            var user = await users.GetUserAsync(HttpContext.User);
            if (user == null)
            {
                if (DirtyPrompt == "none")
                {
                    var app = await applications.FindByClientIdAsync(DirtyClientId);
                    if (app == null)
                    {
                        _logger.LogError($"User tried to login with incorrect client id: ${DirtyClientId}");
                        return RedirectToAction(nameof(Login), new { error = LoginErrors.FatalInvalidClient });
                    }
                    return Redirect(QueryHelpers.AddQueryString(app.RedirectUri, "error", "login_required"));
                }
                return RedirectToAction(nameof(Login), new { ReturnUrl = Request.GetEncodedUrl() });
            }


            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null)
            {
                Console.WriteLine("response", response.Error);
                // User might have incorrect cookie, log out and try again
                // TODO: Can there be login loop here?
                await signInManager.SignOutAsync();
                return Redirect(Request.GetEncodedUrl());
            }

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                return RedirectToAction(nameof(Login), new { error = LoginErrors.FatalRequestNull });
            }

            var application = await applications.FindByClientIdAsync(request.ClientId);
            if (application == null)
            {
                _logger.LogError($"User tried to login with incorrect client id: ${request.ClientId}");
                return RedirectToAction(nameof(Login), new { error = LoginErrors.FatalInvalidClient });
            }

            // Check if the application is official (registered in settings) and
            // accept any request by default
            if (officialApplications.Value.Where(x => x.ClientId == request.ClientId).Count() != 0)
            {
                return await Accept(users, applications, options);
            }
            
            var appName = await applications.GetDisplayNameAsync(application);
            var inputs = "";
            foreach (var item in request.Parameters)
            { 
                var key = WebUtility.HtmlEncode(item.Key);
                var value = WebUtility.HtmlEncode(item.Value);
                inputs = inputs + $@"<input type=""hidden"" name=""{key}"" value=""{value}"" />";
            }

            var data = JsonConvert.SerializeObject(new
            {
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
                    {brandingHtml?.Value?.Authorize}
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

        [Authorize(Policy = "COOKIES"), HttpPost("Authorize/[action]")] // TODO: Anti forgery token
        public virtual async Task<IActionResult> Accept(
            [FromServices] OpenIddictUserManager<User> users,
            [FromServices] OpenIddictApplicationManager<OpenIddictApplication> applications,
            [FromServices] IOptions<OpenIddictOptions> options)
        {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null)
            {
                // TODO: Is response required to be passed here?
                return RedirectToAction(nameof(Login), new { error = LoginErrors.FatalResponseError });
            }

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                return RedirectToAction(nameof(Login), new { error = LoginErrors.FatalRequestNull });
            }

            // Retrieve the user data using the unique identifier.
            var user = await users.GetUserAsync(User);
            if (user == null)
            {
                return RedirectToAction(nameof(Login), new { error = LoginErrors.FatalUserNotFound });
            }

            // Create a new ClaimsIdentity containing the claims that
            // will be used to create an id_token, a token or a code.
            var identity = await users.CreateIdentityAsync(user, request.GetScopes());
            Debug.Assert(identity != null);

            var application = await applications.FindByClientIdAsync(request.ClientId);
            if (application == null)
            {
                return RedirectToAction(nameof(Login), new { error = LoginErrors.FatalInvalidClient });
            }

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                options.Value.AuthenticationScheme);

            ticket.SetResources(request.GetResources());
            ticket.SetScopes(request.GetScopes());

            AddLoggedInClient(HttpContext, request.ClientId);

            // Returning a SignInResult will ask ASOS to serialize the specified identity to build appropriate tokens.
            // Note: you should always make sure the identities you return contain ClaimTypes.NameIdentifier claim.
            // In this sample, the identity always contains the name identifier returned by the external provider.
            return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
        }

        [Authorize(Policy = "COOKIES"), HttpPost("Authorize/[action]")]
        public async Task<IActionResult> Deny(
            [FromServices] IOptions<OpenIddictOptions> options,
            [FromServices] SignInManager<User> signInManager
        )
        {
            var response = HttpContext.GetOpenIdConnectResponse();
            if (response != null)
            {
                return RedirectToAction(nameof(Login), new
                {
                    error = LoginErrors.FatalResponseError
                });
            }

            var request = HttpContext.GetOpenIdConnectRequest();
            if (request == null)
            {
                return RedirectToAction(nameof(Login), new
                {
                    error = LoginErrors.FatalRequestNull
                });
            }

            await RemoveAndLogoutClient(HttpContext, request.ClientId, signInManager);

            // Notify ASOS that the authorization grant has been denied by the resource owner.
            // Note: OpenIdConnectServerHandler will automatically take care of redirecting
            // the user agent to the client application using the appropriate response_mode.
            return Forbid(options.Value.AuthenticationScheme);
        }

        /// <summary>
        /// Add logged in client to cookies
        /// </summary>
        /// <param name="httpContext"></param>
        /// <param name="clientId"></param>
        private void AddLoggedInClient(HttpContext httpContext, string clientId)
        {
            List<string> LoggedInClients = (HttpContext.Request.Cookies["LoggedInClients"]?.Split(',') ?? new string[] { }).ToList();
            if (!LoggedInClients.Contains(clientId))
            {
                LoggedInClients.Add(clientId);
                HttpContext.Response.Cookies.Append("LoggedInClients", string.Join(",", LoggedInClients), new CookieOptions
                {
                    HttpOnly = true,
                    Path = "/OpenId/"
                });
            }
        }

        /// <summary>
        /// Remove logged in client from a cookie, if it's the last one also logout the user from API
        /// </summary>
        /// <param name="httpContext"></param>
        /// <param name="clientId"></param>
        /// <param name="signInManager"></param>
        /// <returns></returns>
        private async Task<bool> RemoveAndLogoutClient(HttpContext httpContext, string clientId, SignInManager<User> signInManager)
        {
            IEnumerable<string> LoggedInClients = HttpContext.Request.Cookies["LoggedInClients"]?.Split(',') ?? new string[] { };
            if (LoggedInClients.Contains(clientId))
            {
                LoggedInClients = LoggedInClients.Except(new[] { clientId });
                HttpContext.Response.Cookies.Append("LoggedInClients", string.Join(",", LoggedInClients), new CookieOptions
                {
                    HttpOnly = true,
                    Path = "/OpenId/"
                });
            } else
            {
                return false;
            }

            if (LoggedInClients.Count() == 0)
            {
                HttpContext.Response.Cookies.Delete("LoggedInClients", new CookieOptions
                {
                    HttpOnly = true,
                    Path = "/OpenId/"
                });
                await signInManager.SignOutAsync();
            }

            return true;
        }

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
    }
}