using System;
using AspNetApiMonolithSample.Api.EntityFramework;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Reflection;
using System.Threading.Tasks;

namespace AspNetApiMonolithSample.Api.Mvc
{
    public class ApiErrorFilter : Attribute, IExceptionFilter
    {
        public void OnException(ExceptionContext context)
        {
            if (context.Exception is ApiError)
            {
                context.Result = (context.Exception as ApiError).GetResult();
                context.Exception = null;
                context.ExceptionHandled = true;
            }
            else if (context.Exception is EntityNotFoundException)
            {
                context.Result = new NotFound().GetResult();
                context.Exception = null;
                context.ExceptionHandled = true;
            }
            else if (context.Exception is EntityListEmptyException)
            {
                context.Result = new NotFound().GetResult();
                context.Exception = null;
                context.ExceptionHandled = true;
            }
        }
    }
}