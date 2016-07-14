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

    abstract public class ApiError : Exception
    {
        public int? StatusCode { get; set; }

        virtual public ObjectResult GetResult()
        {
            return new ObjectResult(new ErrorValue<object>()
            {
                Error = GetType().Name,
                Data = null
            })
            {
                StatusCode = StatusCode
            };
        }
    }

    abstract public class ApiError<T> : ApiError
        where 
            T : class, new()
    {
        public T JsonData { get; set; }

        override public ObjectResult GetResult()
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
        public ValidationError(ModelStateDictionary modelState)
        {
            StatusCode = StatusCodes.Status400BadRequest;
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
            StatusCode = StatusCodes.Status400BadRequest;
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
            StatusCode = StatusCodes.Status401Unauthorized;
        }
    }

    public class Forbidden : ApiError
    {
        public Forbidden()
        {
            StatusCode = StatusCodes.Status403Forbidden;
        }
    }

    public class UndefinedError : ApiError
    {
        public UndefinedError()
        {
            StatusCode = StatusCodes.Status400BadRequest;
        }
    }
}