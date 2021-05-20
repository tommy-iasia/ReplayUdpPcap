using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace ReplayUdpPcap
{
    class Program
    {
        static void Main(string[] args)
        {
            var file = args.FirstOrDefault() ?? throw new ArgumentException(".pcap file is not provided");

            var rate = int.Parse(args.Skip(1).FirstOrDefault() ?? "10");
            Console.WriteLine($"Send rate: {rate}p/s");

            var cancellationSource = new CancellationTokenSource();
            _ = SendAsync(file, rate, cancellationSource.Token);

            Console.WriteLine("Please any key to stop...");
            Console.ReadLine();

            cancellationSource.Cancel();
            Console.WriteLine("End");
        }

        static async Task SendAsync(string file, int rate, CancellationToken cancellation)
        {
            var stopwatch = Stopwatch.StartNew();
            try
            {
                using var udpClient = new UdpClient();
                var count = 0;

                var captures = Read(file);

                Console.WriteLine("Send started");

                foreach (var (capture, ipPacket, udpPacket) in captures)
                {
                    var address = ipPacket.DestinationAddress.ToString();

                    var requireTime = ++count * 1000 / rate;
                    var requirePause = requireTime - (int)stopwatch.Elapsed.TotalMilliseconds;
                    if (requirePause > 0)
                    {
                        await Task.Delay(requirePause, cancellation);
                    }

                    cancellation.ThrowIfCancellationRequested();

                    if (count % rate == 0)
                    {
                        Console.WriteLine($"sending {count}th packet...");
                    }

                    udpClient.Send(
                        udpPacket.PayloadData, udpPacket.PayloadData.Length,
                        address, udpPacket.DestinationPort);
                }

                Console.WriteLine("Send completed");
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e);
                throw;
            }
        }

        private static IEnumerable<(RawCapture capture, IPv4Packet ipPacket, UdpPacket udpPacket)> Read(string file)
        {
            var device = new CaptureFileReaderDevice(file);
            device.Open();

            RawCapture capture;
            while ((capture = device.GetNextPacket()) != null)
            {
                var packet = Packet.ParsePacket(capture.LinkLayerType, capture.Data);
                if (packet.PayloadPacket is not IPv4Packet ipPacket)
                {
                    Console.WriteLine($"Skip packet {packet.PayloadPacket}");
                    continue;
                }

                if (ipPacket.Protocol != PacketDotNet.ProtocolType.Udp)
                {
                    Console.WriteLine($"Skip packet of protocol {ipPacket.Protocol}");
                    continue;
                }

                var udpPacket = packet.Extract<UdpPacket>();

                yield return (capture, ipPacket, udpPacket);
            }

            device.Close();
        }
    }
}
