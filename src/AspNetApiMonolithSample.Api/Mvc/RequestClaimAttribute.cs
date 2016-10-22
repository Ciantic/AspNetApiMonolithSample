using System;
using System.Threading.Tasks;
using AspNetApiMonolithSample.Api.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AspNetApiMonolithSample.Api.Mvc
{
    /// <summary>
    /// Claim request binder
    /// </summary>
    public class RequestClaimBinder : IModelBinder
    {

        public Task BindModelAsync(ModelBindingContext bindingContext)
        {
            var claimType = "";
            if (bindingContext.BindingSource is ClaimBindingSource)
            {
                claimType = (bindingContext.BindingSource as ClaimBindingSource).ClaimType;
            }
            var val = bindingContext.HttpContext.User.FindFirst(claimType);
            if (val != null)
            {
                bindingContext.Result = ModelBindingResult.Success(StringToType(val.Value, bindingContext.ModelType));
            } else
            {
                throw new NotAuthorized();
            }
            return Task.CompletedTask;
        }

        private object StringToType(string value, Type targetType)
        {
            if (typeof(string) == targetType)
            {
                return value;
            } else if (typeof(int) == targetType)
            {
                return int.Parse(value);
            } else
            {
                throw new FormatException("Claim binding type is unknown");
            }
        }
    }

    public class ClaimBindingSource : BindingSource
    {
        public string ClaimType { get; set; }
        public ClaimBindingSource(string claimType, string id, string displayName, bool isGreedy, bool isFromRequest) : base(id, displayName, isGreedy, isFromRequest)
        {
            ClaimType = claimType;
        }
    }

    /// <summary>
    /// Get the request user claim value
    /// </summary>
    [AttributeUsage(AttributeTargets.Parameter | AttributeTargets.Property, AllowMultiple = true, Inherited = true)]
    public class RequestClaimAttribute : Attribute, IBinderTypeProviderMetadata
    {
        private string _claimType;
        public RequestClaimAttribute(string claimType)
        {
            _claimType = claimType;
        }

        public BindingSource BindingSource
        {
            get
            {
                return new ClaimBindingSource(
                    claimType: _claimType,
                    id: "RequestClaim",
                    displayName: "Request claim binder",
                    isGreedy: false,
                    isFromRequest: false)
                {
                    
                };
            }
        }

        Type IBinderTypeProviderMetadata.BinderType
        {
            get
            {
                return typeof(RequestClaimBinder);
            }
        }

    }
}