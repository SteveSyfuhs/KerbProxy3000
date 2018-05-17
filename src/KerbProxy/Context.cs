using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;
using static KerbProxy.NativeMethods;

namespace KerbProxy
{
    internal abstract class Context
    {
        protected Context(AuthenticationSettings settings, IProxyLogger logger)
        {
            Settings = settings;
            Logger = logger;

            CredentialHandle = AcquireCredential();
        }

        protected SECURITY_HANDLE CredentialHandle { get; }

        protected abstract string Mechanism { get; }

        protected AuthenticationSettings Settings { get; }

        protected IProxyLogger Logger { get; }

        protected virtual SECURITY_HANDLE AcquireCredential()
        {
            IntPtr pAuthData = IntPtr.Zero;

            SECURITY_HANDLE phCredential = default(SECURITY_HANDLE);

            var result = AcquireCredentialsHandle_0(
                null,
                Mechanism,
                SECPKG_CRED_INBOUND,
                IntPtr.Zero,
                ref pAuthData,
                IntPtr.Zero,
                IntPtr.Zero,
                ref phCredential,
                IntPtr.Zero
            );

            if (result < 0)
            {
                var ex = new Win32Exception(result);

                throw ex;
            }

            return phCredential;
        }

        public abstract Task<ProxyAuthenticationContext> Accept(SessionEventArgsBase session, string token);
    }
}