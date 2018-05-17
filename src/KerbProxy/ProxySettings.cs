using System.Collections.Generic;

namespace KerbProxy
{
    public class ProxySettings
    {
        public string CertificateAuthority { get; set; }

        public int ListenPort { get; set; }

        //new[] { "Negotiate", "Kerberos", "NTLM" }
        public IEnumerable<string> AuthenticationSchemes { get; set; }

        public bool SetSystemProxy { get; set; }

        public AuthenticationSettings Authentication { get; set; }
    }

    public class ProxyCredential
    {
        public string UserName { get; set; }

        public string Password { get; set; }

        public string Domain { get; set; }
    }

    public class AuthenticationSettings
    {
        public string NtlmKey { get; set; }

        public bool IncludeMetadataHeaders { get; set; }

        public ProxyCredential AcquisitionCredentials { get; set; }
    }
}
