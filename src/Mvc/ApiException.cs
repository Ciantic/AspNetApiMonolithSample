using Microsoft.AspNetCore.Mvc;

namespace AspNetApiMonolithSample.Mvc
{
    sealed public class ApiException : System.Exception
    {
        public ObjectResult Result { get; }
        
        public ApiException(ObjectResult Result) {
            this.Result = Result;
        }
    }
}