# KerbProxy3000
An attempt at building a standalone proxy that requests Negotiate, NTLM, and Kerberos authentication for a given request.

## Building

This currently requires a custom build of the Titanium-Web-Proxy library. It includes a few tweaks to make it work with NTLM, Kerb, etc. You can find the PR and branch here: 

https://github.com/justcoding121/Titanium-Web-Proxy/pull/448

## Running

Build the thing and as a result you should have a console application and a settings file. This file contains settings used by the proxy to process requests.

You can just start the proxy. It doesn't have any command line arguments.

To kill the proxy hit CTRL+C.

Note that NTLM currently just prompts for a token. The proxy will treat any presented NTLM ticket as valid. This is intentional for now. Eventually it'll be dealt with. Kerberos will be authenticated correctly, but it requires a little setup on the AD side of things. You will need to create a service account with SPN for the proxy, and set it's password in the settings file.

## Settings

*ListenPort*: The port the proxy listens on. Defaults to 8000. Keep it above 1000 if you don't want to run as an administrator.

*SetSystemProxy*: Set this to true if you want the proxy to automatically change Windows settings so everything flows through this proxy. Probably not a good idea because it'll force you to authenticate every single request. It's recommended you point a specific application at this proxy instead.

*AuthenticationSchemes*: This is the list of supported schemes that the proxy will respond to the caller with. 

"Authentication": This contains settings for use by proxy to decode real tickets. The proxy will attempt to include authenticated details in the response headers if it succeeds.
