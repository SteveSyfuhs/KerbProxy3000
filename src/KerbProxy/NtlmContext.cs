using System;
using System.ComponentModel;
using System.Text;
using System.Threading.Tasks;
using Titanium.Web.Proxy.EventArguments;
using Titanium.Web.Proxy.Models;
using static KerbProxy.NativeMethods;

namespace KerbProxy
{
    internal class NtlmContext : Context
    {
        public NtlmContext(AuthenticationSettings settings, IProxyLogger logger)
            : base(settings, logger)
        {

        }

        protected override string Mechanism => "Negotiate";

        protected override SECURITY_HANDLE AcquireCredential()
        {
            if (Settings.AcquisitionCredentials == null ||
                string.IsNullOrWhiteSpace(Settings.AcquisitionCredentials.UserName) ||
                string.IsNullOrWhiteSpace(Settings.AcquisitionCredentials.Password))
            {
                return base.AcquireCredential();
            }

            SEC_WINNT_AUTH_IDENTITY pAuthData = new SEC_WINNT_AUTH_IDENTITY(
                Settings.AcquisitionCredentials.Domain,
                Settings.AcquisitionCredentials.UserName,
                Settings.AcquisitionCredentials.Password,
                SEC_WINNT_AUTH_IDENTITY_FLAGS.Unicode
            );

            SECURITY_HANDLE phCredential = default(SECURITY_HANDLE);

            var result = AcquireCredentialsHandle_1(
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
                throw new Win32Exception(result);
            }

            return phCredential;
        }

        private const ContextFlags Flags = ContextFlags.AcceptExtendedError;

        public override Task<ProxyAuthenticationContext> Accept(SessionEventArgsBase session, string token)
        {
            var phCredential = CredentialHandle;

            var pInput = new SecBufferDesc(Convert.FromBase64String(token));

            var result = AcceptSecurityContext_0(
                ref phCredential,
                IntPtr.Zero,
                ref pInput,
                Flags,
                SECURITY_NETWORK_DREP,
                out SECURITY_HANDLE phNewContext,
                out SecBufferDesc pOutput,
                out ContextFlags pfContextAttr,
                out SECURITY_INTEGER ptsTimeStamp
            );

            if (result < 0)
            {
                throw new Win32Exception(result);
            }

            if (result == SEC_I_CONTINUE_NEEDED)
            {
                return Task.FromResult(new ProxyAuthenticationContext
                {
                    Result = ProxyAuthenticationResult.ContinuationNeeded,
                    Continuation = Convert.ToBase64String(pOutput.ReadBytes())
                });
            }

            if (result == SEC_E_OK)
            {
                return Task.FromResult(new ProxyAuthenticationContext
                {
                    Result = ProxyAuthenticationResult.Success
                });
            }

            return Task.FromResult(new ProxyAuthenticationContext
            {
                Result = ProxyAuthenticationResult.Failure
            });
        }
    }
}
