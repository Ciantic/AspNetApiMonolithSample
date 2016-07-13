using System;
using AspNetApiMonolithSample.Api.EntityFramework;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Reflection;

namespace AspNetApiMonolithSample.Api.Mvc
{
    public class ApiErrorFilter : Attribute, IExceptionFilter
    {
        public void OnException(ExceptionContext context)
        {
            if (typeof(ApiError<>).IsAssignableFrom(context.Exception.GetType()))
            {
                context.Result = (context.Exception as ApiError<object>).GetResult();
                context.Exception = null;
            }
            else if (context.Exception is EntityNotFoundException)
            {
                context.Result = new NotFound().GetResult();
                context.Exception = null;
            }
            else if (context.Exception is EntityListEmptyException)
            {
                context.Result = new NotFound().GetResult();
                context.Exception = null;
            }
        }
    }
}