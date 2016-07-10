using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AspNetApiMonolithSample.Mvc
{
    abstract public class ApiErrorResult: ObjectResult {

        protected ApiErrorResult(object Data = null) : base(null)
        {
            this.Value = new
            {
                Error = GetType().Name.Replace("Result", ""),
                Data = Data
            };
            StatusCode = StatusCodes.Status400BadRequest;
        }
        
        // Helper for ApiException
        public ApiException Exception() {
            return new ApiException(this);
        }
    }
    
    public class ValidationErrorResult: ApiErrorResult {
        public ValidationErrorResult(ModelStateDictionary modelState): 
            base(new {
                Fields = modelState.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
                )
            })
        {
            
        }
        
        public ValidationErrorResult(IEnumerable<String> messages): 
            base(new {
                Messages = messages
            })
        {
            
        }
    }
    
    public class NotFoundResult: ApiErrorResult {
        public NotFoundResult() : base() {
            StatusCode = StatusCodes.Status404NotFound;
        }
    }
    
    public class NotAuthorizedResult: ApiErrorResult {
        public NotAuthorizedResult() : base() {
            StatusCode = StatusCodes.Status403Forbidden;
        }
    }

    public class NotAuhenticated : ApiErrorResult
    {
        public NotAuhenticated() : base()
        {
            StatusCode = StatusCodes.Status401Unauthorized;
        }
    }
}