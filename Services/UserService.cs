using System.Security.Claims;
using System.Threading.Tasks;
using AspNetApiMonolithSample.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace AspNetApiMonolithSample.Services
{
    public class UserService
    {
        private readonly UserManager<User> _userManager;

        private readonly SignInManager<User> _signInManager;

        private readonly ILogger _logger;

        public UserService(
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            ILoggerFactory loggerFactory)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = loggerFactory.CreateLogger<AccountController>();
        }

        public async Task<User> LoginAsync(string email, string passwordPlain)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return null;
            }
            var res = await _signInManager.PasswordSignInAsync(user, passwordPlain, false, false);
            if (res.Succeeded)
            {
                return user;
            }
            return null;
        }
        
        public async Task<User> LoggedInAsync(ClaimsPrincipal p) {
            return await _userManager.GetUserAsync(p);
        }
        
        public async Task LogoutAsync() {
            await _signInManager.SignOutAsync();
        }
    }
}