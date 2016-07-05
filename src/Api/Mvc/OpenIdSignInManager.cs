using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

// For more information on enabling MVC for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace Api.Mvc
{
    public class OpenIdSignInManager<TUser> : SignInManager<TUser>
        where TUser : class
    {
        private readonly IHttpContextAccessor contextAccessor;
        public OpenIdSignInManager(UserManager<TUser> userManager,
            IHttpContextAccessor contextAccessor,
            IUserClaimsPrincipalFactory<TUser> claimsFactory,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<SignInManager<TUser>> logger)
            : base(userManager, contextAccessor, claimsFactory, optionsAccessor, logger)
        {
            this.contextAccessor = contextAccessor;
        }

        public override async Task SignOutAsync()
        {
            // TODO: GET CLIENT ID FROM post_logout_redirect_uri
            var clientId = contextAccessor.HttpContext.Request.Query["client_id"];
            if (this.RemoveAndLogoutClient(contextAccessor.HttpContext, clientId))
            {
                // TODO: REDIRECT LLOOOPP?
            }
            await base.SignOutAsync();
        }

        public override async Task SignInAsync(TUser user, bool isPersistent, string authenticationMethod = null)
        {
            var clientId = contextAccessor.HttpContext.Request.Query["client_id"];
            AddLoggedInClient(contextAccessor.HttpContext, clientId);
            await base.SignInAsync(user, isPersistent, authenticationMethod);
        }



        /// <summary>
        /// Add logged in client to cookies
        /// 
        /// TODO: MOVE TO OpenIdSignInManager
        /// </summary>
        /// <param name="httpContext"></param>
        /// <param name="clientId"></param>
        private void AddLoggedInClient(HttpContext httpContext, string clientId)
        {
            List<string> LoggedInClients = (httpContext.Request.Cookies["LoggedInClients"]?.Split(',') ?? new string[] { }).ToList();
            if (!LoggedInClients.Contains(clientId))
            {
                LoggedInClients.Add(clientId);
                httpContext.Response.Cookies.Append("LoggedInClients", string.Join(",", LoggedInClients), new CookieOptions
                {
                    HttpOnly = true,
                    Path = "/OpenId/"
                });
            }
        }

        /// <summary>
        /// Remove logged in client from a cookie, if it's the last one also logout the user from API
        /// 
        /// TODO: MOVE TO OpenIdSignInManager
        /// </summary>
        /// <param name="httpContext"></param>
        /// <param name="clientId"></param>
        /// <param name="signInManager"></param>
        /// <returns></returns>
        private bool RemoveAndLogoutClient(HttpContext httpContext, string clientId)
        {
            IEnumerable<string> LoggedInClients = httpContext.Request.Cookies["LoggedInClients"]?.Split(',') ?? new string[] { };
            if (LoggedInClients.Contains(clientId))
            {
                LoggedInClients = LoggedInClients.Except(new[] { clientId });
                httpContext.Response.Cookies.Append("LoggedInClients", string.Join(",", LoggedInClients), new CookieOptions
                {
                    HttpOnly = true,
                    Path = "/OpenId/"
                });
            }
            else
            {
                return false;
            }

            if (LoggedInClients.Count() == 0)
            {
                httpContext.Response.Cookies.Delete("LoggedInClients", new CookieOptions
                {
                    HttpOnly = true,
                    Path = "/OpenId/"
                });
                return true;
            }

            return false;
        }
    }
}

