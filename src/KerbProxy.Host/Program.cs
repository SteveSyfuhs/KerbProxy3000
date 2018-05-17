using Microsoft.Extensions.Configuration;
using System;
using System.Threading;

namespace KerbProxy.Host
{
    class Program
    {
        static void Main(string[] args)
        {
            var config = new ConfigurationBuilder()
               .AddJsonFile("settings.json", optional: true, reloadOnChange: true).Build();

            var proxySettings = config.Get<ProxySettings>();

            var wait = new ManualResetEvent(false);

            var proxy = new ProxyService(proxySettings) { Logger = new ProxyLogger(Console.Out) };

            proxy.Start();

            wait.WaitOne();
        }
    }
}
