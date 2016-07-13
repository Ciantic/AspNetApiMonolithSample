using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AspNetApiMonolithSample.Api.Mvc
{
    public class ErrorValue<T>
    {
        public string Error { get; set; } = "";
        public T Data { get; set; }
    }

    abstract public class ApiError : ApiError<object>
    {

    }

    abstract public class ApiError<T> : Exception
        where 
            T : class, new()
    {
        public T JsonData { get; set; }
        public int? StatusCode { get; set; }

        public ObjectResult GetResult()
        {
            return new ObjectResult(new ErrorValue<T>()
            {
                Error = GetType().Name,
                Data = JsonData
            })
            {
                StatusCode = StatusCode
            };
        }
    }

    public class ValidationErrorData
    {
        public Dictionary<string, string[]> Fields { get; set; }
        public string[] Messages { get; set; }
    }
    
    public class ValidationError: ApiError<ValidationErrorData> {
        public ValidationError(ModelStateDictionary modelState) {
            JsonData = new ValidationErrorData()
            {
                Fields = modelState.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
                )
            };
        }
        
        public ValidationError(IEnumerable<String> messages)
        {
            JsonData = new ValidationErrorData()
            {
                Messages = messages.ToArray()
            };
        }
    }
    
    public class NotFound: ApiError {
        public NotFound() {
            StatusCode = StatusCodes.Status404NotFound;
        }
    }
    
    public class NotAuthorized: ApiError
    {
        public NotAuthorized() {
            StatusCode = StatusCodes.Status403Forbidden;
        }
    }

    public class NotAuhenticated : ApiError
    {
        public NotAuhenticated()
        {
            StatusCode = StatusCodes.Status401Unauthorized;
        }
    }
}