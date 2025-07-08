using System;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;

namespace PingoMeter
{
    public static class Utils
    {
        /// <summary>
        /// Return true if app running on Windows 8 or next versions.
        /// </summary>
        public static bool IsWindows8Next()
        {
            try
            {
                string productName =
                    (string)Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue("ProductName");
                return productName.StartsWith("Windows 8") || productName.StartsWith("Windows 10");
            }
            catch
            {
                return false;
            }
        }
    }

    public static class PingUtils
    {
        /// <summary>
        /// Pass in the IP you want to ping as a string along with the name of the NIC on your machine that
        /// you want to send the ping from.
        /// </summary>
        /// <param name="ipToPing">The destination IP as a string ex. '10.10.10.1'</param>
        /// <param name="nicName">The name of the NIC ex. 'LECO Hardware'.  Non-case sensitive.</param>
        /// <returns></returns>
        public static bool PingIpFromNic(string ipToPing, string nicName)
        {
            var sourceIpStr = GetIpOfNicFromName(nicName);

            if (sourceIpStr == "")
            {
                MessageBox.Show($"Unable to find an ip for the nic name of {nicName}");
                return false;
            }

            var p = Send(
                srcAddress: IPAddress.Parse(sourceIpStr),
                destAddress: IPAddress.Parse(ipToPing));

            return p.Status == IPStatus.Success;
        }

        /// <summary>
        /// Pass in the name of a NIC on your machine and this method will return the IPV4 address of it.
        /// </summary>
        /// <param name="nicName">The name of the NIC you want the IP of ex. 'TE Hardware'</param>
        /// <returns></returns>
        public static string GetIpOfNicFromName(string nicName)
        {
            var adapters = NetworkInterface.GetAllNetworkInterfaces();

            foreach (var adapter in adapters)
            {
                // Ignoring case in NIC name 
                if (!string.Equals(adapter.Name, nicName, StringComparison.CurrentCultureIgnoreCase)) continue;
                foreach (var uni in adapter.GetIPProperties().UnicastAddresses.Where(x => x.Address.AddressFamily == AddressFamily.InterNetwork))
                {
                    // Only return IPv4 addresses
                    return uni.Address.ToString();
                }
            }
            return "";
        }

        public static PingReply Send(IPAddress srcAddress, IPAddress destAddress,
            int timeout = 5000,
            byte[] buffer = null, PingOptions po = null)
        {
            if (destAddress == null || destAddress.AddressFamily != AddressFamily.InterNetwork ||
                destAddress.Equals(IPAddress.Any))
                throw new ArgumentException();

            //Defining pinvoke args
            var source = srcAddress == null ? 0 : BitConverter.ToUInt32(srcAddress.GetAddressBytes(), 0);

            var destination = BitConverter.ToUInt32(destAddress.GetAddressBytes(), 0);

            var sendBuffer = buffer ?? new byte[] { };

            var options = new Interop.Option
            {
                Ttl = (po == null ? (byte)255 : (byte)po.Ttl),
                Flags = (po == null ? (byte)0 : po.DontFragment ? (byte)0x02 : (byte)0) //0x02
            };

            var fullReplyBufferSize =
                Interop.ReplyMarshalLength +
                sendBuffer.Length; //Size of Reply struct and the transmitted buffer length.

            var allocSpace =
                Marshal.AllocHGlobal(
                    fullReplyBufferSize); // unmanaged allocation of reply size. TODO Maybe should be allocated on stack
            try
            {
                var start = DateTime.Now;
                var nativeCode = Interop.IcmpSendEcho2Ex(
                    Interop.IcmpHandle, //_In_      HANDLE IcmpHandle,
                    Event: default, //_In_opt_  HANDLE Event,
                    apcRoutine: default, //_In_opt_  PIO_APC_ROUTINE ApcRoutine,
                    apcContext: default, //_In_opt_  PVOID ApcContext
                    sourceAddress: source, //_In_      IPAddr SourceAddress,
                    destinationAddress: destination, //_In_      IPAddr DestinationAddress,
                    requestData: sendBuffer, //_In_      LPVOID RequestData,
                    requestSize: (short)sendBuffer.Length, //_In_      WORD RequestSize,
                    requestOptions: ref options, //_In_opt_  PIP_OPTION_INFORMATION RequestOptions,
                    replyBuffer: allocSpace, //_Out_     LPVOID ReplyBuffer,
                    replySize: fullReplyBufferSize, //_In_      DWORD ReplySize,
                    timeout: timeout //_In_      DWORD Timeout
                );

                var duration = DateTime.Now - start;

                var reply = (Interop.Reply)Marshal.PtrToStructure(allocSpace,
                    typeof(Interop.Reply)); // Parse the beginning of reply memory to reply struct

                byte[] replyBuffer = null;
                if (sendBuffer.Length != 0)
                {
                    replyBuffer = new byte[sendBuffer.Length];
                    Marshal.Copy(allocSpace + Interop.ReplyMarshalLength, replyBuffer, 0,
                        sendBuffer.Length); //copy the rest of the reply memory to managed byte[]
                }

                if (nativeCode == 0) //Means that native method is faulted.
                    return new PingReply(nativeCode, reply.Status,
                        new IPAddress(reply.Address), duration);
                else
                    return new PingReply(nativeCode, reply.Status,
                        new IPAddress(reply.Address), reply.RoundTripTime,
                        replyBuffer);
            }
            finally
            {
                Marshal.FreeHGlobal(allocSpace); //free allocated space
            }
        }


        /// <summary>Interoperability Helper
        ///     <see cref="http://msdn.microsoft.com/en-us/library/windows/desktop/bb309069(v=vs.85).aspx" />
        /// </summary>
        public static class Interop
        {
            private static IntPtr? _icmpHandle;
            private static int? _replyStructLength;

            /// <summary>Returns the application legal icmp handle. Should be close by IcmpCloseHandle
            ///     <see cref="http://msdn.microsoft.com/en-us/library/windows/desktop/aa366045(v=vs.85).aspx" />
            /// </summary>
            public static IntPtr IcmpHandle
            {
                get
                {
                    if (_icmpHandle == null)
                    {
                        _icmpHandle = IcmpCreateFile();
                        //TODO Close Icmp Handle appropriate
                    }

                    return _icmpHandle.GetValueOrDefault();
                }
            }

            /// <summary>Returns the the marshaled size of the reply struct.</summary>
            public static int ReplyMarshalLength
            {
                get
                {
                    if (_replyStructLength == null)
                    {
                        _replyStructLength = Marshal.SizeOf(typeof(Reply));
                    }

                    return _replyStructLength.GetValueOrDefault();
                }
            }


            [DllImport("Iphlpapi.dll", SetLastError = true)]
            private static extern IntPtr IcmpCreateFile();

            [DllImport("Iphlpapi.dll", SetLastError = true)]
            private static extern bool IcmpCloseHandle(IntPtr handle);

            [DllImport("Iphlpapi.dll", SetLastError = true)]
            public static extern uint IcmpSendEcho2Ex(IntPtr icmpHandle, IntPtr Event, IntPtr apcRoutine, IntPtr apcContext, uint sourceAddress,
                UInt32 destinationAddress, byte[] requestData, short requestSize, ref Option requestOptions, IntPtr replyBuffer, int replySize,
                int timeout);

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
            public struct Option
            {
                public byte Ttl;
                public readonly byte Tos;
                public byte Flags;
                public readonly byte OptionsSize;
                public readonly IntPtr OptionsData;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
            public struct Reply
            {
                public readonly UInt32 Address;
                public readonly int Status;
                public readonly int RoundTripTime;
                public readonly short DataSize;
                public readonly short Reserved;
                public readonly IntPtr DataPtr;
                public readonly Option Options;
            }
        }

        [Serializable]
        public class PingReply
        {
            private Win32Exception _exception;

            internal PingReply(uint nativeCode, int replyStatus, IPAddress ipAddress, TimeSpan duration)
            {
                NativeCode = nativeCode;
                IpAddress = ipAddress;
                if (Enum.IsDefined(typeof(IPStatus), replyStatus))
                    Status = (IPStatus)replyStatus;
            }

            internal PingReply(uint nativeCode, int replyStatus, IPAddress ipAddress, int roundTripTime, byte[] buffer)
            {
                NativeCode = nativeCode;
                IpAddress = ipAddress;
                RoundtripTime = roundTripTime;
                Buffer = buffer;
                if (Enum.IsDefined(typeof(IPStatus), replyStatus))
                    Status = (IPStatus)replyStatus;
            }

            /// <summary>Native result from <code>IcmpSendEcho2Ex</code>.</summary>
            public uint NativeCode { get; }

            public IPStatus Status { get; } = IPStatus.Unknown;

            /// <summary>The source address of the reply.</summary>
            public IPAddress IpAddress { get; }

            public byte[] Buffer { get; }

            public long RoundtripTime { get; } = -1;

            public Win32Exception Exception
            {
                get
                {
                    if (Status != IPStatus.Success)
                        return _exception ?? (_exception = new Win32Exception((int)NativeCode, Status.ToString()));
                    else
                        return null;
                }
            }

            public override string ToString()
            {
                if (Status == IPStatus.Success)
                    return Status + " from " + IpAddress + " in " + RoundtripTime + " ms with " + Buffer.Length + " bytes";
                else if (Status != IPStatus.Unknown)
                    return Status + " from " + IpAddress;
                else
                    return Exception.Message + " from " + IpAddress;
            }
        }
    }
}