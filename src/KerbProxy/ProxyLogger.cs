using System;
using System.IO;

namespace KerbProxy
{
    public interface IProxyLogger
    {
        void Write(string line);
        void Error(Exception kvex);
    }

    public class ProxyLogger : IProxyLogger
    {
        private readonly TextWriter write;

        public ProxyLogger(TextWriter stream)
        {
            write = stream;
        }

        public void Error(Exception kvex)
        {
            Write(kvex.ToString());
        }

        public void Write(string line)
        {
            var timestamp = DateTimeOffset.UtcNow.ToString("u");

            write.WriteLine($"[{timestamp}] {line}\r\n\r\n");
        }
    }
}
