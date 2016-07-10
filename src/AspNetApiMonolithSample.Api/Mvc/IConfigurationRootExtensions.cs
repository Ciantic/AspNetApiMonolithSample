using System;
using Microsoft.Extensions.Configuration;

namespace AspNetApiMonolithSample.EntityFramework
{
    public static class IConfigurationRootExtensions
    {
        public static string GetOrFail(this IConfigurationRoot configuration, string path)
        {
            var val = configuration[path];
            if (val == null || val.Length == 0) {
                throw new Exception($"Configuration is missing for '{path}'");
            }
            return val;
        }

    }
}