using AspNetApiMonolithSample.Api.EntityFramework;
using AspNetApiMonolithSample.Api.Models;
using Microsoft.Extensions.DependencyInjection;
using MailKit.Net.Smtp;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using MimeKit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetApiMonolithSample.Api.Services
{
    /// <summary>
    /// Email Sender singleton implemented using MailKit and MimeKit
    /// 
    /// This interface is relatively naive, it does not include ability to send emails to  
    /// multiple users etc.
    /// 
    /// Stores the Email to database, and has simple batch processing to send 
    /// emails.
    /// </summary>
    public class EmailSender : IEmailSender
    {
        public string FromName { get; set; } = "";
        public string FromEmail { get; set; } = "";
        public string SmtpHost { get; set; } = "";
        public int SmtpPort { get; set; } = 0;
        public bool SmtpSsl { get; set; } = false;
        public string SmtpUsername { get; set; } = "";
        public string SmtpPassword { get; set; } = "";

        private readonly IServiceProvider _services;

        public EmailSender(IServiceProvider services)
        {
            _services = services;
        }

        /// <summary>
        /// Send email
        /// 
        /// Puts an email to processing queue and triggers the processing queue in new thread.
        /// </summary>
        public async Task Send(string toEmail, string toName, string subject, string body)
        {
            var appDbContextOpts = _services.GetService<DbContextOptions<AppDbContext>>();
            using (var appDbContext = new AppDbContext(appDbContextOpts))
            {
                appDbContext.Emails.Add(new Email()
                {
                    FromEmail = FromEmail,
                    FromName = FromName,
                    ToEmail = toEmail,
                    ToName = toName,
                    Body = body,
                    Subject = subject,
                    CreatedAt = DateTime.Now,
                });
                await appDbContext.SaveChangesAsync();
            }
                
            StartProcessQueue();
        }

        private Task _processingQueue = Task.CompletedTask;
        private object _processingQueueLock = new object();

        /// <summary>
        /// Start processing the queue
        /// </summary>
        private void StartProcessQueue()
        {
            _processingQueue.ContinueWith(t1 =>
            {
                lock (_processingQueueLock) { 
                    _processingQueue = ProcessQueue().ContinueWith(t2 =>
                    {
                        var logger = _services.GetService<ILogger<EmailService>>();
                        logger.LogError($"Unhandled error during processing email queue: {t2.Exception.Message}", t2.Exception);
                        
                    }, TaskContinuationOptions.OnlyOnFaulted);
                }
            });
        }

        /// <summary>
        /// Processes the stored email queue
        /// 
        /// It marks all mails it's going to process with Guid, this ensures multiple 
        /// instances can handle them concurrently.
        /// 
        /// When delivery has been done it marks the mails with SentAt.
        /// </summary>
        private async Task ProcessQueue()
        {
            Thread.Sleep(500); // Gather all emails inserted in last 500ms, and process them

            var logger = _services.GetService<ILogger<EmailService>>();
            var appDbContextOpts = _services.GetService<DbContextOptions<AppDbContext>>();
            using (var appDbContext = new AppDbContext(appDbContextOpts))
            {
                var processGuid = Guid.NewGuid();

                // Mark mails as being processed at
                var emails = await appDbContext.Emails.Where(x => x.ProcessGuid == Guid.Empty && x.SentTries < 3).ToListAsync();
                if (emails.Count == 0)
                {
                    return;
                }

                foreach (var e in emails)
                {
                    e.ProcessGuid = processGuid;
                }

                // This only succeeds if the emails has not changed due to concurrency stamp
                try
                {
                    await appDbContext.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException) {}

                await ProcessSend(appDbContext, logger, processGuid);

            }

        }

        /// <summary>
        /// Send the emails of the process
        /// </summary>
        private async Task ProcessSend(AppDbContext appDbContext, ILogger logger, Guid processGuid)
        {
            var emails = await appDbContext.Emails.Where(x => x.ProcessGuid == processGuid).ToListAsync();
            if (emails.Count == 0)
            {
                return;
            }

            try
            {
                using (var client = new SmtpClient())
                {
                    client.AuthenticationMechanisms.Remove("XOAUTH2");
                    client.Connect(SmtpHost, SmtpPort, SmtpSsl);
                    client.Authenticate(SmtpUsername, SmtpPassword);

                    // Mark emails as sent if they didn't throw exception
                    foreach (var email in emails)
                    {
                        await SendMail(client, email);
                    }

                    client.Disconnect(true);
                }
            }
            catch (Exception ex) when (
                ex is MailKit.Security.AuthenticationException || 
                ex is MailKit.ProtocolException
            )
            {
                logger.LogError($"Unhandled error during smtp connection, email process GUID {processGuid}", ex);
            }
            finally
            {
                // Save sent at values
                await appDbContext.SaveChangesAsync();
            }
        }

        private async Task SendMail(SmtpClient client, Email email)
        {
            var m = new MimeMessage();
            m.From.Add(new MailboxAddress(email.FromName, email.FromEmail));
            m.To.Add(new MailboxAddress(email.ToName, email.ToEmail));
            m.Subject = email.Subject;
            
            var bodyBuilder = new BodyBuilder();
            bodyBuilder.HtmlBody = email.Body;
            m.Body = bodyBuilder.ToMessageBody();
            
            /*
            m.Body = new TextPart("plain")
            {
                Text = email.Body
            };
            */

            try
            {
                await client.SendAsync(m);
                email.SentAt = DateTime.Now;
            }
            catch (Exception ex) when (
                ex is MailKit.ServiceNotConnectedException ||
                ex is MailKit.ServiceNotAuthenticatedException ||
                ex is MailKit.CommandException ||
                ex is MailKit.ProtocolException
            )
            {
                email.SentTries += 1;
                email.ResultMessage = $"{ex.GetType().Name}: {ex.Message}";
                email.ProcessGuid = Guid.Empty;
            }
        }
    }
}
