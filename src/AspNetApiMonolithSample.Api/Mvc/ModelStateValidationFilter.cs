using System;
using Microsoft.AspNetCore.Mvc.Filters;

namespace AspNetApiMonolithSample.Api.Mvc
{
    public class ModelStateValidationFilter : Attribute, IActionFilter
    {
        public void OnActionExecuting(ActionExecutingContext context)
        {
            if (!context.ModelState.IsValid)
            {
                context.Result = new ValidationErrorResult(context.ModelState);
            }
        }

        public void OnActionExecuted(ActionExecutedContext context) { }
    }
}