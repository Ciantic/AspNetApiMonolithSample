using System;
using System.Threading.Tasks;
using AspNetApiMonolithSample.Api.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AspNetApiMonolithSample.Api.Mvc
{
    /// <summary>
    /// Request user modelbinder from UserManager automatically
    /// </summary>
    public class RequestUserModelBinder : IModelBinder
    {
        private readonly UserManager<User> _userManager;
        public RequestUserModelBinder(UserManager<User> userManager)
        {
            _userManager = userManager;
        }

        public async Task BindModelAsync(ModelBindingContext bindingContext)
        {
            var user = await _userManager.GetUserAsync(bindingContext.ActionContext.HttpContext.User);
            if (user == null)
            {
                throw new NotAuhenticated();
            } else { 
                bindingContext.Result = ModelBindingResult.Success(user);
            }
        }
    }

    /// <summary>
    /// Get the request user from UserManager automatically
    /// </summary>
    [AttributeUsage(AttributeTargets.Parameter | AttributeTargets.Property, AllowMultiple = true, Inherited = true)]
    public class RequestUserAttribute : Attribute, IBinderTypeProviderMetadata
    {
        public BindingSource BindingSource
        {
            get
            {
                return new BindingSource(
                    id: "RequestUser",
                    displayName: "RequestUser",
                    isGreedy: false,
                    isFromRequest: false);
            }
        }

        Type IBinderTypeProviderMetadata.BinderType
        {
            get
            {
                return typeof(RequestUserModelBinder);
            }
        }

    }
}