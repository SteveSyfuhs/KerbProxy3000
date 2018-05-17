using Newtonsoft.Json;
using System;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using Titanium.Web.Proxy;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;

namespace KerbProxy
{
    public class ProxyService
    {
        private readonly ProxyServer proxyServer;
        private readonly ExplicitProxyEndPoint explicitEndPoint;

        private readonly ProxySettings settings;

        public ProxyService(ProxySettings settings)
        {
            this.settings = settings;

            proxyServer = new ProxyServer();

            explicitEndPoint = new ExplicitProxyEndPoint(IPAddress.Any, settings.ListenPort, false);

            explicitEndPoint.BeforeTunnelConnectRequest += OnBeforeTunnelConnect;

            proxyServer.AddEndPoint(explicitEndPoint);
        }

        public IProxyLogger Logger { get; set; }

        private void Log(string line)
        {
            Logger?.Write(line);
        }

        public void Start()
        {
            proxyServer.CertificateManager.RootCertificateIssuerName = settings.CertificateAuthority;

            proxyServer.CertificateManager.TrustRootCertificate(true);

            proxyServer.BeforeRequest += OnRequest;
            proxyServer.BeforeResponse += OnResponse;

            proxyServer.ServerCertificateValidationCallback += OnCertificateValidation;
            proxyServer.ClientCertificateSelectionCallback += OnCertificateSelection;

            proxyServer.AuthenticateSchemeFunc = AuthenticateScheme;
            proxyServer.SupportedAuthenticationSchemes = settings.AuthenticationSchemes;

            proxyServer.Start();

            foreach (var endPoint in proxyServer.ProxyEndPoints)
            {
                Log(string.Format(
                    "Listening on '{0}' endpoint at Ip {1} and port: {2} ",
                    endPoint.GetType().Name,
                    endPoint.IpAddress,
                    endPoint.Port
                    )
                );
            }

            if (settings.SetSystemProxy)
            {
                proxyServer.SetAsSystemHttpProxy(explicitEndPoint);
                proxyServer.SetAsSystemHttpsProxy(explicitEndPoint);
            }
        }

        private Task<ProxyAuthenticationContext> AuthenticateScheme(
            SessionEventArgsBase session,
            string scheme,
            string token
        )
        {
            Log($"{scheme}: {token}");

            switch (scheme.ToLowerInvariant())
            {
                case "kerberos":
                case "negotiate":
                    return Negotiate(session, token);
                case "ntlm":
                    return Ntlm(session, token);
            }

            return Task.FromResult(ProxyAuthenticationContext.Succeeded());
        }

        //private readonly object syncNtlm = new object();

        //private NtlmContext ntlmContext;

        private Task<ProxyAuthenticationContext> Ntlm(SessionEventArgsBase session, string token)
        {
            if (token.StartsWith("TlRMTVNTUA"))
            {
                session.SetUserData("request.ntlm", "true");
            }

            return Task.FromResult(ProxyAuthenticationContext.Succeeded());

            //if (ntlmContext == null)
            //{
            //    lock (syncNtlm)
            //    {
            //        if (ntlmContext == null)
            //        {
            //            ntlmContext = new NtlmContext(settings.Authentication, Logger);
            //        }
            //    }
            //}

            //return await ntlmContext.Accept(session, token);
        }

        private readonly object syncNego = new object();
        private NegotiateContext negoContext;

        private async Task<ProxyAuthenticationContext> Negotiate(SessionEventArgsBase session, string token)
        {
            if (negoContext == null)
            {
                lock (syncNego)
                {
                    if (negoContext == null)
                    {
                        negoContext = new NegotiateContext(settings.Authentication, Logger);
                    }
                }
            }

            var result = await negoContext.Accept(session, token);

            if (result != null &&
                result.Result == ProxyAuthenticationResult.ContinuationNeeded &&
                result.Continuation == null)
            {
                return await Ntlm(session, token);
            }

            return result;
        }

        public void Stop()
        {
            proxyServer.Stop();
        }

        private static readonly Task Completed = Task.CompletedTask;

        private Task OnBeforeTunnelConnect(object sender, TunnelConnectSessionEventArgs e)
        {
            Log($"OnBeforeTunnelConnect: {e.WebSession.Request.Host}");

            return Completed;
        }

        private Task OnCertificateSelection(object sender, CertificateSelectionEventArgs e)
        {
            Log($"OnCertificateSelection: {e.TargetHost}");

            return Completed;
        }

        private Task OnCertificateValidation(object sender, CertificateValidationEventArgs e)
        {
            //e.IsValid = true;

            return Completed;
        }

        private Task OnResponse(object sender, SessionEventArgs e)
        {
            Log($"Responding: {e.WebSession.Response.StatusCode}");

            if (settings.Authentication.IncludeMetadataHeaders)
            {
                try
                {
                    AttachMetadataHeaders(e);
                }
                catch (Exception ex)
                {
                    Logger.Error(ex);
                }
            }

            return Completed;
        }

        private void AttachMetadataHeaders(SessionEventArgs e)
        {
            var identity = e.GetUserData<ClaimsIdentity>("request.identity");

            if (identity != null)
            {
                var claims = identity.Claims
                    .GroupBy(c => c.Type)
                    .ToDictionary(c => c.Key, c => c.Select(v => v.Value));

                var header = JsonConvert.SerializeObject(claims);

                e.WebSession.Response.Headers.AddHeader("x-kp3-identity", header);
            }

            var ntlmish = e.GetUserData<string>("request.ntlm");

            if (!string.IsNullOrWhiteSpace(ntlmish))
            {
                e.WebSession.Response.Headers.AddHeader("x-kp3-ntlm", ntlmish);
            }
        }

        private Task OnRequest(object sender, SessionEventArgs e)
        {
            return Completed;
        }
    }
}
