using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace KerbProxy
{
    static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct SEC_WINNT_AUTH_IDENTITY
        {
            public SEC_WINNT_AUTH_IDENTITY(
                string domain, 
                string username, 
                string password, 
                SEC_WINNT_AUTH_IDENTITY_FLAGS flag
            )
            {
                this.Domain = domain;
                this.DomainLength = domain.Length;

                this.User = username;
                this.UserLength = username.Length;

                this.Password = password;
                this.PasswordLength = password.Length;

                this.Flags = flag;
            }

            [MarshalAs(UnmanagedType.LPWStr)]
            public string User;

            public int UserLength;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string Domain;

            public int DomainLength;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string Password;

            public int PasswordLength;

            public SEC_WINNT_AUTH_IDENTITY_FLAGS Flags;
        }

        internal enum SEC_WINNT_AUTH_IDENTITY_FLAGS : int
        {
            Ansi = 1,

            Unicode = 2
        }
        
        internal enum SecBufferType : int
        {
            SECBUFFER_VERSION = 0,
            SECBUFFER_EMPTY = 0,
            SECBUFFER_DATA = 1,
            SECBUFFER_TOKEN = 2
        }

        [Flags]
        internal enum ContextFlags
        {
            Zero = 0,
            // The server in the transport application can
            // build new security contexts impersonating the
            // client that will be accepted by other servers
            // as the client's contexts.
            Delegate = 0x00000001,
            // The communicating parties must authenticate
            // their identities to each other. Without MutualAuth,
            // the client authenticates its identity to the server.
            // With MutualAuth, the server also must authenticate
            // its identity to the client.
            MutualAuth = 0x00000002,
            // The security package detects replayed packets and
            // notifies the caller if a packet has been replayed.
            // The use of this flag implies all of the conditions
            // specified by the Integrity flag.
            ReplayDetect = 0x00000004,
            // The context must be allowed to detect out-of-order
            // delivery of packets later through the message support
            // functions. Use of this flag implies all of the
            // conditions specified by the Integrity flag.
            SequenceDetect = 0x00000008,
            // The context must protect data while in transit.
            // Confidentiality is supported for NTLM with Microsoft
            // Windows NT version 4.0, SP4 and later and with the
            // Kerberos protocol in Microsoft Windows 2000 and later.
            Confidentiality = 0x00000010,
            UseSessionKey = 0x00000020,
            AllocateMemory = 0x00000100,

            // Connection semantics must be used.
            Connection = 0x00000800,

            // Client applications requiring extended error messages specify the
            // ISC_REQ_EXTENDED_ERROR flag when calling the InitializeSecurityContext
            // Server applications requiring extended error messages set
            // the ASC_REQ_EXTENDED_ERROR flag when calling AcceptSecurityContext.
            InitExtendedError = 0x00004000,
            AcceptExtendedError = 0x00008000,
            // A transport application requests stream semantics
            // by setting the ISC_REQ_STREAM and ASC_REQ_STREAM
            // flags in the calls to the InitializeSecurityContext
            // and AcceptSecurityContext functions
            InitStream = 0x00008000,
            AcceptStream = 0x00010000,
            // Buffer integrity can be verified; however, replayed
            // and out-of-sequence messages will not be detected
            InitIntegrity = 0x00010000,       // ISC_REQ_INTEGRITY
            AcceptIntegrity = 0x00020000,       // ASC_REQ_INTEGRITY

            InitManualCredValidation = 0x00080000,   // ISC_REQ_MANUAL_CRED_VALIDATION
            InitUseSuppliedCreds = 0x00000080,   // ISC_REQ_USE_SUPPLIED_CREDS
            InitIdentify = 0x00020000,   // ISC_REQ_IDENTIFY
            AcceptIdentify = 0x00080000,   // ASC_REQ_IDENTIFY

            ProxyBindings = 0x04000000,   // ASC_REQ_PROXY_BINDINGS
            AllowMissingBindings = 0x10000000,   // ASC_REQ_ALLOW_MISSING_BINDINGS

            UnverifiedTargetName = 0x20000000,   // ISC_REQ_UNVERIFIED_TARGET_NAME
        }


        internal const int SECPKG_CRED_INBOUND = 0x00000001;
        internal const int SECPKG_CRED_OUTBOUND = 0x00000002;

        internal const int SEC_E_OK = 0x00000000;
        internal const int SEC_E_NO_CREDENTIALS = unchecked((int)0x8009030E);
        internal const int SEC_I_CONTINUE_NEEDED = 0x90312;
        internal const int SEC_I_INCOMPLETE_CREDENTIALS = 0x90320;

        internal const int SECURITY_NATIVE_DREP = 0x10;
        internal const int SECURITY_NETWORK_DREP = 0x00;

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecBuffer
        {
            public int cbBuffer;
            public SecBufferType BufferType;
            public IntPtr pvBuffer;

            public SecBuffer(int bufferSize)
            {
                cbBuffer = bufferSize;
                BufferType = SecBufferType.SECBUFFER_TOKEN;
                pvBuffer = Marshal.AllocHGlobal(bufferSize);
            }

            public SecBuffer(byte[] secBufferBytes)
            {
                cbBuffer = secBufferBytes.Length;
                BufferType = SecBufferType.SECBUFFER_TOKEN;
                pvBuffer = Marshal.AllocHGlobal(cbBuffer);
                Marshal.Copy(secBufferBytes, 0, pvBuffer, cbBuffer);
            }

            public void Dispose()
            {
                if (pvBuffer != IntPtr.Zero)
                {
                    // Freeing memory

                    Marshal.FreeHGlobal(pvBuffer);
                    pvBuffer = IntPtr.Zero;
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SecBufferDesc : IDisposable
        {
            private SecBufferType ulVersion;
            public int cBuffers;
            public IntPtr pBuffers; //Point to SecBuffer

            public SecBufferDesc(int bufferSize)
                : this(new SecBuffer(bufferSize))
            {
            }

            public SecBufferDesc(byte[] secBufferBytes)
                : this(new SecBuffer(secBufferBytes))
            {
            }

            private SecBufferDesc(SecBuffer secBuffer)
            {
                ulVersion = SecBufferType.SECBUFFER_VERSION;

                cBuffers = 1;

                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(secBuffer));

                Marshal.StructureToPtr(secBuffer, pBuffers, false);
            }

            public void Dispose()
            {
                if (pBuffers != IntPtr.Zero)
                {
                    ForEachBuffer(thisSecBuffer => thisSecBuffer.Dispose());

                    // Freeing pBuffers

                    Marshal.FreeHGlobal(pBuffers);
                    pBuffers = IntPtr.Zero;
                }
            }

            private void ForEachBuffer(Action<SecBuffer> onBuffer)
            {
                for (int Index = 0; Index < cBuffers; Index++)
                {
                    int CurrentOffset = Index * Marshal.SizeOf(typeof(SecBuffer));

                    SecBuffer thisSecBuffer = (SecBuffer)Marshal.PtrToStructure(
                        IntPtr.Add(
                            pBuffers,
                            CurrentOffset
                        ),
                        typeof(SecBuffer)
                    );

                    onBuffer(thisSecBuffer);
                }
            }

            public byte[] ReadBytes()
            {
                if (cBuffers <= 0)
                {
                    return new byte[0];
                }

                var bufferList = new List<byte[]>();

                ForEachBuffer(thisSecBuffer =>
                {
                    if (thisSecBuffer.cbBuffer <= 0)
                    {
                        return;
                    }

                    var buffer = new byte[thisSecBuffer.cbBuffer];

                    Marshal.Copy(thisSecBuffer.pvBuffer, buffer, 0, thisSecBuffer.cbBuffer);

                    bufferList.Add(buffer);
                });

                var finalLen = bufferList.Sum(b => b.Length);

                var finalBuffer = new byte[finalLen];

                var position = 0;

                for (var i = 0; i < bufferList.Count; i++)
                {
                    Buffer.BlockCopy(bufferList[i], 0, finalBuffer, position, bufferList[i].Length - 1);

                    position += bufferList[i].Length - 1;
                }

                return finalBuffer;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        };

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_HANDLE
        {
            public ulong dwLower;
            public ulong dwUpper;

            public bool IsSet { get { return dwLower > 0 && dwUpper > 0; } }
        };

        //SEC_WINNT_AUTH_IDENTITY

        [DllImport("secur32",
        CharSet = CharSet.Auto,
        BestFitMapping = false,
        ThrowOnUnmappableChar = true,
        EntryPoint = "AcquireCredentialsHandle")]
        internal static extern int AcquireCredentialsHandle_0(
        string pszPrincipal, //SEC_CHAR*
        string pszPackage, //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
        int fCredentialUse,
        IntPtr PAuthenticationID,//_LUID AuthenticationID,//pvLogonID, //PLUID
        ref IntPtr pAuthData,
        IntPtr pGetKeyFn, //SEC_GET_KEY_FN
        IntPtr pvGetKeyArgument, //PVOID
        ref SECURITY_HANDLE phCredential, //SecHandle //PCtxtHandle ref
        IntPtr ptsExpiry //PTimeStamp //TimeStamp ref
    );

        [DllImport("secur32",
            CharSet = CharSet.Auto,
            BestFitMapping = false,
            ThrowOnUnmappableChar = true,
            EntryPoint = "AcquireCredentialsHandle")]
        internal static extern int AcquireCredentialsHandle_1(
            string pszPrincipal, //SEC_CHAR*
            string pszPackage, //SEC_CHAR* //"Kerberos","NTLM","Negotiative"
            int fCredentialUse,
            IntPtr PAuthenticationID,//_LUID AuthenticationID,//pvLogonID, //PLUID
            ref SEC_WINNT_AUTH_IDENTITY pAuthData,
            IntPtr pGetKeyFn, //SEC_GET_KEY_FN
            IntPtr pvGetKeyArgument, //PVOID
            ref SECURITY_HANDLE phCredential, //SecHandle //PCtxtHandle ref
            IntPtr ptsExpiry //PTimeStamp //TimeStamp ref
        );

        [DllImport("secur32",
            EntryPoint = "InitializeSecurityContext",
            CharSet = CharSet.Auto,
            BestFitMapping = false,
            ThrowOnUnmappableChar = true,
            SetLastError = true)]
        internal static extern int InitializeSecurityContext_0(
            ref SECURITY_HANDLE phCredential,//PCredHandle
            IntPtr phContext, //PCtxtHandle
            string pszTargetName,
            int fContextReq,
            int Reserved1,
            int TargetDataRep,
            IntPtr pInput, //PSecBufferDesc SecBufferDesc
            int Reserved2,
            ref SECURITY_HANDLE phNewContext, //PCtxtHandle
            ref SecBufferDesc pOutput, //PSecBufferDesc SecBufferDesc
            out ContextFlags pfContextAttr, //managed ulong == 64 bits!!!
            IntPtr ptsExpiry //PTimeStamp
        );

        [DllImport("secur32",
            EntryPoint = "InitializeSecurityContext",
            CharSet = CharSet.Auto,
            BestFitMapping = false,
            ThrowOnUnmappableChar = true,
            SetLastError = true)]
        internal static extern int InitializeSecurityContext_1(
            ref SECURITY_HANDLE phCredential,//PCredHandle
            SECURITY_HANDLE phContext, //PCtxtHandle
            string pszTargetName,
            int fContextReq,
            int Reserved1,
            int TargetDataRep,
            SecBufferDesc pInput, //PSecBufferDesc SecBufferDesc
            int Reserved2,
            ref SECURITY_HANDLE phNewContext, //PCtxtHandle
            ref SecBufferDesc pOutput, //PSecBufferDesc SecBufferDesc
            out ContextFlags pfContextAttr, //managed ulong == 64 bits!!!
            IntPtr ptsExpiry //PTimeStamp
        );

        [DllImport("secur32.dll", SetLastError = true, EntryPoint = "AcceptSecurityContext")]
        internal static extern int AcceptSecurityContext_0(
            ref SECURITY_HANDLE phCredential,
            IntPtr phContext,
            ref SecBufferDesc pInput,
            ContextFlags fContextReq,
            uint TargetDataRep,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out ContextFlags pfContextAttr,    //managed ulong == 64 bits!!!
            out SECURITY_INTEGER ptsTimeStamp
        );

        [DllImport("secur32.dll", SetLastError = true, EntryPoint = "AcceptSecurityContext")]
        internal static extern int AcceptSecurityContext_1(
            ref SECURITY_HANDLE phCredential,
            SECURITY_HANDLE phContext,
            ref SecBufferDesc pInput,
            ContextFlags fContextReq,
            uint TargetDataRep,
            out SECURITY_HANDLE phNewContext,
            out SecBufferDesc pOutput,
            out ContextFlags pfContextAttr,    //managed ulong == 64 bits!!!
            out SECURITY_INTEGER ptsTimeStamp
        );

        [DllImport("secur32.dll")]
        public static extern int DeleteSecurityContext(SECURITY_HANDLE phContext);
    }
}
