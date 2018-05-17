using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;

namespace KerbProxy
{
    internal class NegotiateContext : Context
    {
        public NegotiateContext(AuthenticationSettings settings, IProxyLogger logger)
            : base(settings, logger)
        {
            authenticator = new KerberosAuthenticatorEx(
                new KeyTable(
                    new KerberosKey(
                        settings.NtlmKey
                    )
                )
            );
        }

        protected override NativeMethods.SECURITY_HANDLE AcquireCredential()
        {
            return new NativeMethods.SECURITY_HANDLE();
        }

        protected override string Mechanism => "Negotiate";

        private readonly KerberosAuthenticator authenticator;

        public override async Task<ProxyAuthenticationContext> Accept(SessionEventArgsBase session, string token)
        {
            ClaimsIdentity identity;

            try
            {
                identity = await authenticator.Authenticate(token);
            }
            catch (Exception kvex)
            {
                Logger.Error(kvex);

                return ProxyAuthenticationContext.Failed();
            }

            if (identity == null)
            {
                return new ProxyAuthenticationContext { Result = ProxyAuthenticationResult.ContinuationNeeded };
            }

            session.SetUserData("request.identity", identity);

            return new ProxyAuthenticationContext { Result = ProxyAuthenticationResult.Success };
        }

        private class KerberosAuthenticatorEx : KerberosAuthenticator
        {
            public KerberosAuthenticatorEx(KeyTable keytab) : base(keytab)
            {
            }

            protected override ClaimsIdentity ConvertTicket(DecryptedData data)
            {
                if (data == null || data.Ticket == null)
                {
                    return null;
                }

                return base.ConvertTicket(data);
            }
        }
    }
}
