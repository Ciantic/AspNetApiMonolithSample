using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System;
using System.Reflection;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json.Serialization;

namespace AspNetApiMonolithSample.Api.Mvc
{
    internal class TypescriptGenerator
    {
        internal class TypescriptType
        {
            public Type TheType { get; set; }
            public string Definition { get; set; }
        }

        private readonly Dictionary<Type, TypescriptType> _typescriptTypeList = new Dictionary<Type, TypescriptType>();
        private readonly MvcJsonOptions _mvcJsonOpts;
        private readonly IContractResolver _jsonContractResolver;

        public TypescriptGenerator(
            IOptions<MvcJsonOptions> mvcJsonOpts
        )
        {
            _jsonContractResolver = mvcJsonOpts.Value.SerializerSettings.ContractResolver ?? new DefaultContractResolver();
            _mvcJsonOpts = mvcJsonOpts.Value;
        }

        public string Generate(Type type)
        {
            TypescriptType tsType;

            if (_typescriptTypeList.ContainsKey(type))
            {
                tsType = _typescriptTypeList[type];
            } else
            {
                tsType = new TypescriptType()
                {
                    TheType = type,
                    Definition = generateDefinition(type),
                };
                _typescriptTypeList.Add(type, tsType);
            }

            return tsType.Definition;
        }

        private string generateDefinition(Type target)
        {
            if (PrimitiveTypeMap.ContainsKey(target))
            {
                return PrimitiveTypeMap[target];
            }
            var jsonContract = _jsonContractResolver.ResolveContract(target);
            
            if (jsonContract is JsonPrimitiveContract)
            {
                var primitiveContract = (JsonPrimitiveContract)jsonContract;
                var type = Nullable.GetUnderlyingType(primitiveContract.UnderlyingType) ?? primitiveContract.UnderlyingType;

                // TODO: if (type.GetTypeInfo().IsEnum) ...

                if (PrimitiveTypeMap.ContainsKey(type))
                {
                    return PrimitiveTypeMap[type];
                }
            }

            if (jsonContract is JsonDictionaryContract) { 
                var dictContract = (JsonDictionaryContract)jsonContract;
                var kType = Generate(dictContract.DictionaryKeyType);
                var vType = Generate(dictContract.DictionaryValueType);
                return $"{{ [k: {kType}]: {vType} }}";
            }

            if (jsonContract is JsonArrayContract)
            {
                var arrayContract = (JsonArrayContract)jsonContract;
                return $"{Generate(arrayContract.CollectionItemType)}[]";
            }

            if (jsonContract is JsonObjectContract)
            {
                var objectContract = (JsonObjectContract)jsonContract;
                var propTypes = new List<string>();
                foreach (var p in objectContract.Properties)
                {
                    propTypes.Add(p.PropertyName + " : " + Generate(p.PropertyType));
                }
                return $"{{ {string.Join(", ", propTypes)} }}";

            }

            return "any";
        }

        private static readonly Dictionary<Type, string> PrimitiveTypeMap = new Dictionary<Type, string>
        {
            { typeof(string), "string" },
            { typeof(short), "number" },
            { typeof(ushort), "number" },
            { typeof(int), "number" },
            { typeof(uint), "number" },
            { typeof(long), "number" },
            { typeof(ulong), "number" },
            { typeof(float), "number" },
            { typeof(double), "number" },
            { typeof(decimal), "number" },
            { typeof(byte), "string" },
            { typeof(sbyte), "string" },
            { typeof(byte[]), "string" },
            { typeof(sbyte[]), "string" },
            { typeof(bool), "string" },
            { typeof(DateTime), "string" },
            { typeof(DateTimeOffset), "string" },
            { typeof(Guid), "string" },
        };
    }
    

    public class GenSdkOptions
    {
        public Func<ApiDescription, string> GroupActionsBy { get; set; } = (s => {
            return s.GroupName;
        });
        public string Indent { get; set; } = "    ";
        public string ReturnTypeFormat { get; set; } = "ApiPromise<{type}>";
        public string RequestFunctionFormat { get; set; } = "request(\"{relativePath}\", \"{method}\", {bodyParam})";
        public string ApiOutputFormat { get; set; } = "export default {apiObject};";
        public string OutputPath { get; set; } = "Api.ts";
        public string ApiPromiseBegin { get; set; } = "abstract class ApiPromise<T> extends Promise<T> {";
        public string ApiPromiseErrorFormat { get; set; } = "abstract onError(errorCode: \"{errorName}\", cb: (data: {dataType}) => void);";
        public string ApiPromiseEnd { get; set; } = "}";

        public IEnumerable<string> Headers { get; set; } = new string[] {
            "/* tslint:disable */",
            "// This file is generated from the API. Do not edit this file.",
            "",
        };
        public IEnumerable<string> Imports { get; set; } = new string[] {
            "import { request } from \"./request\"",
            "",
        };

        public string GetApiPromiseErrorFormat(string errorName, string dataType)
        {
            var res = new StringBuilder(ApiPromiseErrorFormat);
            foreach (var kv in new Dictionary<string, string>()
            {
                { "{errorName}", errorName },
                { "{dataType}", dataType },
            })
            {
                res.Replace(kv.Key, kv.Value);
            }
            return res.ToString();
        }

        public string GetApiOutputFormat(string apiObject)
        {
            var res = new StringBuilder(ApiOutputFormat);
            foreach (var kv in new Dictionary<string, string>()
            {
                { "{apiObject}", apiObject },
            })
            {
                res.Replace(kv.Key, kv.Value);
            }
            return res.ToString();
        }

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

        private readonly TypescriptGenerator _tsGen;

        public GenSdk(
            IApiDescriptionGroupCollectionProvider apiDescriptionsProvider, 
            IOptions<MvcJsonOptions> mvcJsonOpts,
            ILogger<GenSdk> logger)
        {
            _logger = logger;
            _apiDescriptionsProvider = apiDescriptionsProvider;
            _jsonSerializerSettings = mvcJsonOpts.Value.SerializerSettings;
            _tsGen = new TypescriptGenerator(mvcJsonOpts);
        }

        public void Generate(GenSdkOptions opts)
        {
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
                        _tsGen.Generate(p.Type);
                        // registry.GetOrRegister(p.Type);
                        apiFunction.InputBodyType = p.Type;
                    }

                    // Get result type
                    if (act.SupportedResponseTypes.Count >= 1) { 
                        var responseType = act.SupportedResponseTypes.First();
                        _tsGen.Generate(responseType.Type);
                        // registry.GetOrRegister(responseType.Type);
                        apiFunction.ResultType = responseType.Type;
                    }

                    var groupName = opts.GroupActionsBy(act);
                    if (groupName == null)
                    {
                        _logger.LogWarning($"Skipping SDK generation for {act.ActionDescriptor.DisplayName}. Group name can't be parsed.");
                        break;
                    }

                    var groups = groupName.Split('.');

                    // Step in to the nesting given in groups 
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

            // var apiObject = allDefinitions.GenTypescript(opts, registry);
            var apiObject = allDefinitions.GenTypescript(opts, _tsGen);
            var output = new List<string>();
            output.AddRange(opts.Headers);
            output.AddRange(opts.Imports);
            output.Add(getApiErrors(opts, _tsGen));
            output.Add(opts.GetApiOutputFormat(apiObject));
            
            // Write only if changed or does not exist
            var outputText = string.Join("\r\n", output);
            var write = true;
            if (File.Exists(opts.OutputPath))
            {
                var fileContents = File.ReadAllText(opts.OutputPath);
                write = fileContents != outputText;
            }

            if (write)
            {
                File.WriteAllText(opts.OutputPath, outputText);
            }
        }

        private class ErrorDefinition
        {
            public string Error { get; set; } = "";
            public Type DataType { get; set; } = null;
        }

        private static string getApiErrors(GenSdkOptions opts, TypescriptGenerator tsGen)
        {
            
            IEnumerable<Type> apiErrors = typeof(ApiError).GetTypeInfo().Assembly
                .GetTypes()
                .Where(t => typeof(ApiError).IsAssignableFrom(t) && !t.GetTypeInfo().IsAbstract)
                .Select(t => t);

            var errorDefinitions = new List<ErrorDefinition>();

            foreach (var t in apiErrors)
            {
                var bt = t.GetTypeInfo().BaseType;

                if (bt == typeof(ApiError))
                {
                    errorDefinitions.Add(new ErrorDefinition()
                    {
                        Error = t.Name,
                        DataType = null
                    });
                    continue;
                }
                else if (bt.IsConstructedGenericType && 
                    bt.GetTypeInfo().GetGenericTypeDefinition() == typeof(ApiError<>))
                {
                    var dataType = bt.GenericTypeArguments[0];
                    tsGen.Generate(dataType);
                    errorDefinitions.Add(new ErrorDefinition()
                    {
                        Error = t.Name,
                        DataType = dataType
                    });
                    continue;
                }
            }

            var output = opts.ApiPromiseBegin;
            var errs = new List<string>();

            foreach (var def in errorDefinitions)
            {
                errs.Add(opts.GetApiPromiseErrorFormat(def.Error, def.DataType != null ? tsGen.Generate(def.DataType) : "null"));
            }

            return indentAllButFirstLine(output + "\r\n" + string.Join("\r\n", errs)) + "\r\n" + opts.ApiPromiseEnd;
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
            string GenTypescript(GenSdkOptions opts, TypescriptGenerator tsGen);

            IDictionary<string, IItem> Children { get; set; }
        }

        private class ApiFunctionItem : IItem
        {
            public string HttpMethod { get; set; } = "";
            public string RelativePath { get; set; } = "";
            public Type InputBodyType { get; set; }
            public Type ResultType { get; set; }
            public IDictionary<string, IItem> Children { get; set; } = new Dictionary<string, IItem>();
            public string GenTypescript(GenSdkOptions opts, TypescriptGenerator tsGen)
            {
                var inputParams = new List<string>();
                var outputValue = "void";
                if (InputBodyType != null)
                {
                    inputParams.Add($"body: {tsGen.Generate(InputBodyType)}");
                }
                if (ResultType != null)
                {
                    outputValue = tsGen.Generate(ResultType);
                }
                var outputFormat = opts.GetReturnTypeFormat(outputValue);
                var requestFormat = opts.GetRequestFunctionFormat(RelativePath, HttpMethod, InputBodyType != null ? "body" : "false");

                return indentAllButFirstLine($"({string.Join(", ", inputParams)}): {outputFormat} =>\r\n{opts.Indent}{requestFormat}");
            }
        }

        /// <summary>
        /// Group of controllers or actions in object
        /// </summary>
        private class ObjectItem : IItem
        {
            public IDictionary<string, IItem> Children { get; set; } = new Dictionary<string, IItem>();
            public string GenTypescript(GenSdkOptions opts, TypescriptGenerator tsGen)
            {
                var parentItems = new List<string>();
                foreach (var p in Children)
                {
                    var item = p.Value.GenTypescript(opts, tsGen);
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
