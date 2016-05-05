using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AspNetApiMonolithSample.Mvc
{
    abstract public class ApiErrorResult: ObjectResult {
        
        protected ApiErrorResult(string name, object Data = null) : base(new {
            Error = name,
            Data = Data
        }) {
            StatusCode = StatusCodes.Status400BadRequest;
        }
        
        // Helper for ApiException
        public ApiException Exception() {
            return new ApiException(this);
        }
    }
    
    public class ValidationErrorResult: ApiErrorResult {
        public ValidationErrorResult(ModelStateDictionary modelState): 
            base("VALIDATION_ERROR", new {
                Fields = modelState.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
                )
            })
        {
            
        }
        
        public ValidationErrorResult(IEnumerable<String> messages): 
            base("VALIDATION_ERROR", new {
                Messages = messages
            })
        {
            
        }
    }
    
    public class NotFoundResult: ApiErrorResult {
        public NotFoundResult() : base("NOT_FOUND") {
            StatusCode = StatusCodes.Status404NotFound;
        }
    }
    
    public class NotAuthorizedResult: ApiErrorResult {
        public NotAuthorizedResult() : base("NOT_AUTHORIZED") {
            StatusCode = StatusCodes.Status401Unauthorized;
        }
    }
}