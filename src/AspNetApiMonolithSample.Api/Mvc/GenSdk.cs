using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using Swashbuckle.Swagger.Model;
using Swashbuckle.SwaggerGen.Generator;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace AspNetApiMonolithSample.Api.Mvc
{
    internal static class SchemaExtension
    {
        /// <summary>
        /// Convert swagger type to TypeScript type
        /// 
        /// See the end of file: 
        /// https://github.com/domaindrivendev/Ahoy/blob/master/src/Swashbuckle.SwaggerGen/Generator/SchemaRegistry.cs
        /// </summary>
        private static string convertToTypescriptType(string swaggerType)
        {
            if (swaggerType == "integer")
            {
                return "number";
            }
            return swaggerType;
        }

        /// <summary>
        /// Generates typescript definition
        /// </summary>
        public static string genTypescriptDefinition(this Schema schema, SchemaRegistry registry)
        {
            return registry.genTypescriptDefinition(schema);
        }

        /// <summary>
        /// Generates typescript definition
        /// </summary>
        public static string genTypescriptDefinition(this SchemaRegistry registry, Type target)
        {
            return registry.genTypescriptDefinition(registry.GetOrRegister(target));
        }

        /// <summary>
        /// Generates typescript definition
        /// </summary>
        public static string genTypescriptDefinition(this SchemaRegistry registry, Schema target)
        {
            if (target.Type != null && target.Type != "object" && target.Properties == null)
            {
                return convertToTypescriptType(target.Type);
            }
            else if (target.Type == "object" && target.Properties != null)
            {
                var subDefs = new List<string>();
                foreach (var p in target.Properties)
                {
                    subDefs.Add($"\"{p.Key}\" : {registry.genTypescriptDefinition(p.Value)}");
                }

                return "{" + string.Join(", ", subDefs) + "}";
            }
            else if (target.Ref != null)
            {
                var regex = new Regex("#/definitions/(.*)");
                var match = regex.Match(target.Ref);
                if (match.Success)
                {
                    return registry.genTypescriptDefinition(registry.Definitions[match.Groups[1].Value]);
                }
            }

            throw new Exception("what?");
        }
    }

    public class GenSdkOptions
    {
        public Func<ApiDescription, string> GroupActionsBy { get; set; } = (s => {
            return s.GroupName;
        });
        public string Indent { get; set; } = "    ";
        public string ReturnTypeFormat { get; set; } = "Promise<{type}>";
        public string RequestFunctionFormat { get; set; } = "request(\"{relativePath}\", \"{method}\", {bodyParam})";
        public string[] Imports { get; set; } = new string[] { "import { request } from \"./request\"" };
        public string OutputPath { get; set; } = "";

        public string GetReturnTypeFormat(string type)
        {
            var res = new StringBuilder(ReturnTypeFormat);
            foreach (var kv in new Dictionary<string, string>()
            {
                { "{type}", type },
            })
            {
                res.Replace(kv.Key, kv.Value);
            }
            return res.ToString();
        }

        public string GetRequestFunctionFormat(string relativePath, string method, string bodyParam)
        {
            var res = new StringBuilder(RequestFunctionFormat);
            foreach (var kv in new Dictionary<string, string>()
            {
                { "{relativePath}", relativePath },
                { "{method}", method },
                { "{bodyParam}", bodyParam },
            })
            {
                res.Replace(kv.Key, kv.Value);
            }
            return res.ToString();
        }
    }

    public class GenSdk
    {
        private readonly IApiDescriptionGroupCollectionProvider _apiDescriptionsProvider;

        private readonly JsonSerializerSettings _jsonSerializerSettings;

        private readonly ILogger<GenSdk> _logger;

        public GenSdk(
            IApiDescriptionGroupCollectionProvider apiDescriptionsProvider, 
            IOptions<MvcJsonOptions> mvcJsonOpts,
            ILogger<GenSdk> logger)
        {
            _logger = logger;
            _apiDescriptionsProvider = apiDescriptionsProvider;
            _jsonSerializerSettings = mvcJsonOpts.Value.SerializerSettings;
        }

        public void Generate(GenSdkOptions opts)
        {
            var registry = new SchemaRegistry(this._jsonSerializerSettings);
            var allDefinitions = new ObjectItem() as IItem;

            foreach (var grp in _apiDescriptionsProvider.ApiDescriptionGroups.Items)
            {
                
                foreach (var act in grp.Items)
                {
                    var apiFunction = new ApiFunctionItem();
                    apiFunction.HttpMethod = act.HttpMethod;
                    apiFunction.RelativePath = act.RelativePath;

                    // Supports at most one parameter, the [FromBody]
                    if (act.ParameterDescriptions.Count > 1)
                    {
                        continue;
                    }

                    // Works only with [FromBody] param for now
                    if (act.ParameterDescriptions.Count == 1) { 
                        var p = act.ParameterDescriptions.First();

                        if (p.Source.Id.ToLower() != "body")
                        {
                            _logger.LogWarning($"Skipping SDK generation for {act.ActionDescriptor.DisplayName}. Only [FromBody] parameters are supported.");
                            continue;
                        }
                        registry.GetOrRegister(p.Type);
                        apiFunction.InputBodyType = p.Type;
                    }

                    // Get result type
                    if (act.SupportedResponseTypes.Count >= 1) { 
                        var responseType = act.SupportedResponseTypes.First();
                        registry.GetOrRegister(responseType.Type);
                        apiFunction.ResultType = responseType.Type;
                    }

                    var groupName = opts.GroupActionsBy(act);
                    if (groupName == null)
                    {
                        _logger.LogWarning($"Skipping SDK generation for {act.ActionDescriptor.DisplayName}. Group name can't be parsed.");
                        break;
                    }

                    var groups = groupName.Split('.');
                    var currDef = allDefinitions;
                    foreach (var g in groups)
                    {
                        if (!currDef.Children.ContainsKey(g))
                        {
                            currDef.Children[g] = new ObjectItem();
                        }
                        currDef = currDef.Children[g];
                    }

                    var nameRegex = new Regex(@".([^.]+) ");
                    var nameMatch = nameRegex.Match(act.ActionDescriptor.DisplayName);
                    if (!nameMatch.Success)
                    {
                        break;
                    }
                    var name = nameMatch.Groups[1].Value;
                    currDef.Children[name] = apiFunction;
                    
                }
            }

            Console.WriteLine(allDefinitions.GenTypescript(opts, registry));
        }

        private static string indentAllButFirstLine(string text, string indent = "    ")
        {
            var lines = text.Split(new string[] { "\r\n" }, StringSplitOptions.None);
            var i = 0;
            foreach (var l in lines)
            {
                if (i > 0)
                {
                    lines[i] = indent + l;
                }
                i++;
            }
            return string.Join("\r\n", lines);
        }

        private interface IItem
        {
            string GenTypescript(GenSdkOptions opts, SchemaRegistry registry);
            IDictionary<string, IItem> Children { get; set; }
        }

        private class ApiFunctionItem : IItem
        {
            public string HttpMethod { get; set; } = "";
            public string RelativePath { get; set; } = "";
            public Type InputBodyType { get; set; }
            public Type ResultType { get; set; }
            public IDictionary<string, IItem> Children { get; set; } = new Dictionary<string, IItem>();
            public string GenTypescript(GenSdkOptions opts, SchemaRegistry registry)
            {
                var inputParams = new List<string>();
                var outputValue = "void";
                if (InputBodyType != null)
                {
                    inputParams.Add($"body: {registry.genTypescriptDefinition(InputBodyType)}");
                }
                if (ResultType != null)
                {
                    outputValue = registry.genTypescriptDefinition(ResultType);
                }
                var outputFormat = opts.GetReturnTypeFormat(outputValue);
                var requestFormat = opts.GetRequestFunctionFormat(RelativePath, HttpMethod, InputBodyType != null ? "body" : "false");

                return $"({string.Join(", ", inputParams)}): {outputFormat} =>\r\n{opts.Indent}{opts.Indent}{requestFormat}";
            }
        }

        /// <summary>
        /// Group of controllers or actions in object
        /// </summary>
        private class ObjectItem : IItem
        {
            public IDictionary<string, IItem> Children { get; set; } = new Dictionary<string, IItem>();
            public string GenTypescript(GenSdkOptions opts, SchemaRegistry registry)
            {
                var parentItems = new List<string>();
                foreach (var p in Children)
                {
                    var item = p.Value.GenTypescript(opts, registry);
                    if (p.Value is ObjectItem)
                    {
                        item = indentAllButFirstLine(item, opts.Indent);
                    }
                    parentItems.Add($"{opts.Indent}{p.Key} : {item}");
                }
                return $"{{\r\n{string.Join(",\r\n", parentItems)}\r\n}}";
            }
        }
    }
}
