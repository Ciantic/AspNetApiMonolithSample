using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetMonolithSample.Services
{
    public interface IEmailSender
    {
        Task Send(string toEmail, string toName, string subject, string body);
    }
}
