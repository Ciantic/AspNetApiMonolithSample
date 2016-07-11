using AspNetApiMonolithSample.Api.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetApiMonolithSample.Api.Services
{
    public sealed class EmailPlaceholders : Dictionary<string, string>
    {
        
    }

    /// <summary>
    /// Email service
    /// 
    /// Creates emails from the templates
    /// </summary>
    public class EmailService
    {
        private readonly ILogger<EmailService> _logger;
        private readonly IEmailSender _emailSender;
        private readonly EmailPlaceholders _emailPlaceholders;
        private readonly IHostingEnvironment _env;
        private readonly FrontendUrls _frontendUrls;

        public EmailService(
            IOptions<FrontendUrls> frontendUrlsOpts,
            IEmailSender emailSender,
            ILogger<EmailService> logger,
            IOptions<EmailPlaceholders> emailPlaceholdersOpts,
            IHostingEnvironment env)
        {
            _frontendUrls = frontendUrlsOpts.Value;
            _logger = logger;
            _env = env;
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

        /// <summary>
        /// Send register email
        /// </summary>
        /// <param name="code">Code for confirmation</param>
        /// <exception cref="IOException">If the email template IO fails</exception>
        public async Task SendRegisterEmail(User user, string code)
        {
            await Send("Register", user.LanguageCode, user.Email, user.FullName, new RegisterEmailModel()
            {
                ConfirmUrl = _frontendUrls.RegisterConfirmEmail
                    .Replace("{code}", WebUtility.UrlEncode(code))
                    .Replace("{email}", WebUtility.UrlEncode(user.Email))
            });
        }

        private class ResetPasswordEmailModel : IEmailModel
        {
            public string ResetUrl { get; set; } = "";
        }

        /// <summary>
        /// Send reset password email
        /// </summary>
        /// <param name="code">Code for confirmation</param>
        /// <exception cref="IOException">If the email template IO fails</exception>
        public async Task SendResetPasswordEmail(User user, string code)
        {
            await Send("ResetPassword", user.LanguageCode, user.Email, user.FullName, new ResetPasswordEmailModel()
            {
                ResetUrl = _frontendUrls.ResetPassword
                    .Replace("{code}", WebUtility.UrlEncode(code))
                    .Replace("{email}", WebUtility.UrlEncode(user.Email))
            });
        }

        /// <summary>
        /// Send the email
        /// 
        /// Looks for templates 
        /// `EmailTemplates/{templateName}(.{languageCode}).Subject.txt` and
        /// `EmailTemplates/{templateName}(.{languageCode}).Body.html`
        /// 
        /// In addition to `model` also Option section `EmailPlaceholders` is used 
        /// in placeholders.
        /// </summary>
        /// <param name="templateName">Name of the template, </param>
        /// <param name="languageCode"></param>
        /// <param name="toEmail"></param>
        /// <param name="toName"></param>
        /// <param name="model">Used as placeholders</param>
        /// <exception cref="IOException">Thrown when the template can't be read</exception>
        /// <returns></returns>
        private async Task Send(string templateName, string languageCode, string toEmail, string toName, IEmailModel model)
        {
            var props = model.GetType().GetProperties();
            
            var subject = new StringBuilder("");
            var body = new StringBuilder("");
            var values = new Dictionary<string, string>();
            var languageSuffix = languageCode != "" ? $".{languageCode}" : "";
            var subjectFileName = Path.Combine(_env.ContentRootPath, "EmailTemplates", $"{templateName}{languageSuffix}.Subject.txt");
            var bodyFileName = Path.Combine(_env.ContentRootPath, "EmailTemplates", $"{templateName}{languageSuffix}.Body.html");

            if (!File.Exists(subjectFileName) || !File.Exists(bodyFileName))
            {
                _logger.LogError($"Email template `{templateName}` does not exist");
                return;
            }

            try
            {
                using (var bodyFile = File.OpenRead(bodyFileName))
                using (var subjectFile = File.OpenRead(subjectFileName))
                {
                    subject = new StringBuilder(new StreamReader(subjectFile).ReadToEnd());
                    body = new StringBuilder(new StreamReader(bodyFile).ReadToEnd());
                }
            }
            catch (IOException e)
            {
                _logger.LogError($"Email template `{templateName}` could not be accessed", e);
                throw;
            }

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

            await _emailSender.Send(toEmail, toName, subject.ToString(), body.ToString());
        }
    }
}
