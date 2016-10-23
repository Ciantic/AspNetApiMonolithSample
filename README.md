# AspNetApiMonolithSample

Project is in expiremental stage, and is not a suitable for use yet.

Monlith Web Api sample used fro ASP.NET Core applications. Uses ASP.NET Core Identity, Entity Framework Core, and other ASP.NET Core libraries.

# Certificate for OpenIddict signing key

test.pfx file for development is generated using command line (in Linux or Windows Bash with openssl):
```
openssl req -new -newkey rsa:2048 -days 999 -nodes -x509 -keyout test.key -out test.cert
openssl pkcs12 -inkey test.key -in test.cert -export -out test.pfx
```


# License

MIT License see LICENSE.txt, portions of the code may be copyrighted to Microsoft under their ASP.NET Core Apache license, see e.g .https://github.com/aspnet/Identity for more information.