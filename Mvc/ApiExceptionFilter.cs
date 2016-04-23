using System;
using AspNetApiMonolithSample.EntityFramework;
using Microsoft.AspNetCore.Mvc.Filters;

namespace AspNetApiMonolithSample.Mvc
{
    public class ApiExceptionFilter : Attribute, IExceptionFilter
    {
        public void OnException(ExceptionContext context)
        {
            if (context.Exception is ApiException)
            {
                context.Result = (context.Exception as ApiException).Result;
                context.Exception = null;
            }
            else if (context.Exception is EntityNotFoundException)
            {
                context.Result = new NotFoundResult();
                context.Exception = null;
            }
            else if (context.Exception is EntityListEmptyException)
            {
                context.Result = new NotFoundResult();
                context.Exception = null;
            }
        }
    }
}