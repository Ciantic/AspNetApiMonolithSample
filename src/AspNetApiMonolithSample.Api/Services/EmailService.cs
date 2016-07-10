using AspNetApiMonolithSample.Api.Models;
using Microsoft.Extensions.Options;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace AspNetApiMonolithSample.Api.Services
{
    public sealed class EmailPlaceholders : Dictionary<string, string>
    {
        
    }

    public class EmailService
    {
        private readonly IEmailSender _emailSender;
        private readonly EmailPlaceholders _emailPlaceholders;

        public EmailService(IEmailSender emailSender, IOptions<EmailPlaceholders> emailPlaceholdersOpts)
        {
            _emailSender = emailSender;
            _emailPlaceholders = emailPlaceholdersOpts.Value;
        }

        private interface IEmailModel
        {

        }

        private class RegisterEmailModel : IEmailModel
        {
            public string ConfirmUrl { get; set; } = "";
        }

        public async Task SendRegisterEmail(User user, string code)
        {
            await Send(user.Email, user.FullName, "Register", new RegisterEmailModel()
            {
                ConfirmUrl = $"http://example.com/{code}"
            });
        }

        public void SendResetPassword(User user)
        {

        }

        private async Task Send(string email, string name, string templateName, IEmailModel model)
        {
            var props = model.GetType().GetProperties();
            
            var subject = new StringBuilder("");
            var body = new StringBuilder("");

            await _emailSender.Send(email, name, subject.ToString(), body.ToString());
        }
    }
}
