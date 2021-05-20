using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;

namespace ReplayUdpPcap
{
    public static class PcapFileReader
    {
        public static IEnumerable<(RawCapture capture, IPv4Packet ipPacket, UdpPacket udpPacket)> Read(string file)
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
