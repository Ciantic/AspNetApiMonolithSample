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
                ConfirmUrl = $"http://example.com/{code}/2"
            });
            await Send(user.Email, user.FullName, "Register", new RegisterEmailModel()
            {
                ConfirmUrl = $"http://example.com/{code}"
            });
        }

        private class ResetPasswordEmailModel : IEmailModel
        {
            public string ResetUrl { get; set; } = "";
        }

        public async Task SendResetPasswordEmail(User user, string code)
        {
            await Send(user.Email, user.FullName, "ResetPassword", new ResetPasswordEmailModel()
            {
                ResetUrl = $"http://example.com/{code}"
            });
        }

        private async Task Send(string email, string name, string templateName, IEmailModel model)
        {
            var props = model.GetType().GetProperties();
            
            var subject = new StringBuilder("");
            var body = new StringBuilder("");
            var values = new Dictionary<string, string>();

            foreach (var p in _emailPlaceholders)
            {
                values.Add(p.Key.ToLower(), p.Value);
            }

            foreach (var p in props)
            {
                values.Add(p.Name.ToLower(), p.GetValue(model) as string);
            }

            foreach (var v in values)
            {
                subject.Replace($"[{v.Key}]", v.Value);
                body.Replace($"[{v.Key}]", v.Value);
            }

            await _emailSender.Send(email, name, subject.ToString(), body.ToString());
        }
    }
}
