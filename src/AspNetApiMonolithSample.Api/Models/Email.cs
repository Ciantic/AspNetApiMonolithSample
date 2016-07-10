using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AspNetApiMonolithSample.Api.Models
{
    /// <summary>
    /// Naive Email storage class.
    /// 
    /// Does not support multiple recievers etc.
    /// </summary>
    public class Email : IEntity<int>
    {
        public int Id { get; set; } = 0;

        [Column(TypeName = "varchar(255)")]
        public string FromName { get; set; } = "";

        [Column(TypeName = "varchar(255)")]
        public string FromEmail { get; set; } = "";

        [Column(TypeName = "varchar(255)")]
        public string ToName { get; set; } = "";

        [Column(TypeName = "varchar(255)")]
        public string ToEmail { get; set; } = "";

        [Column(TypeName = "varchar(1024)")]
        public string Subject { get; set; } = "";

        public string Body { get; set; } = "";

        public int SentTries { get; set; } = 0;

        public string ResultMessage { get; set; } = "";

        public Guid ProcessGuid { get; set; }

        public DateTime CreatedAt { get; set; }

        public DateTime? SentAt { get; set; } = null;

        [Timestamp]
        public byte[] ConcurrencyStamp { get; set; }
    }
}
