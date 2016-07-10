using AspNetApiMonolithSample.Api.Models;
using System.Collections.Generic;
using System.Reflection;
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

        public EmailService(IEmailSender emailSender, EmailPlaceholders emailPlaceholders)
        {
            _emailSender = emailSender;
            _emailPlaceholders = emailPlaceholders;
        }

        private interface IEmailModel
        {

        }

        private class RegisterEmailModel : IEmailModel
        {
            public string ConfirmUrl { get; set; } = "";
        }

        private class RenderedEmailTemplate
        {
            public string Subject { get; set; }
            public string Body { get; set; }
        }

        private RenderedEmailTemplate Render(IEmailModel model, string templateName, string language = "")
        {
            var props = model.GetType().GetProperties();


            return new RenderedEmailTemplate()
            {
                Subject = ""
            };
        }

        private async Task Send(string email, string name, string templateName, IEmailModel model)
        {
            var values = Render(model, templateName);
            await _emailSender.Send(email, name, values.Subject, values.Body);
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
    }
}
