using System;
using System.Threading.Tasks;
using AspNetApiMonolithSample.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AspNetApiMonolithSample.Mvc
{
    /// <summary>
    /// Request user modelbinder from UserManager automatically
    /// </summary>
    public class RequsetUserModelBinder : IModelBinder
    {
        private readonly UserManager<User> _userManager;
        public RequsetUserModelBinder(UserManager<User> userManager)
        {
            _userManager = userManager;
        }

        public async Task BindModelAsync(ModelBindingContext bindingContext)
        {
            var user = await _userManager.GetUserAsync(bindingContext.OperationBindingContext.ActionContext.HttpContext.User);
            bindingContext.Result = ModelBindingResult.Success(bindingContext.ModelName, user);
        }
    }

    /// <summary>
    /// Get the request user from UserManager automatically
    /// </summary>
    [AttributeUsage(AttributeTargets.Parameter | AttributeTargets.Property, AllowMultiple = false, Inherited = true)]
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
                    isFromRequest: true);
            }
        }

        Type IBinderTypeProviderMetadata.BinderType
        {
            get
            {
                return typeof(RequsetUserModelBinder);
            }
        }

    }
}