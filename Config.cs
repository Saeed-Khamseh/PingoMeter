using System.Drawing;
using System.IO;
using System.Net;
using System.Text;

namespace PingoMeter
{
    internal static class Config
    {


        private const string CONF_FILE_NAME = "config.txt";

        public static int Delay = 3000;

        public static int MaxPing;
        public static bool OfflineCounter = true;

        public static Pen BgColor;
        public static Pen GoodColor;
        public static Pen NormalColor;
        public static Pen BadColor;

        public static bool RunOnStartup;

        private static string ipName;
        private static IPAddress ipAddress;
        public static string NetworkInterfaceName = string.Empty;

        public static IPAddress TheIPAddress
        {
            get => ipAddress;
            set
            {
                ipAddress = value;
                ipName = value.ToString();
            }
        }

        public static string GetIPName => ipName;

        public static bool AlarmConnectionLost;
        public static bool AlarmTimeOut;
        public static bool AlarmResumed;

        // sound effects path to .wav (or "(none)")
        public const string NONE_SFX = "(none)";
        public static string SFXConnectionLost;
        public static string SFXTimeOut;
        public static string SFXResumed;

        /// <summary> Use numbers for the ping instead of a graph. </summary>
        public static bool UseNumbers;



        static Config() => Reset();

        public static void SetAll(int delay, int maxPing, Color bgColor, Color goodColor, Color normalColor,
                                  Color badColor, bool runOnStartup, IPAddress address,
                                  bool alarmConnectionLost, bool alarmTimeOut, bool alarmResumed, bool useNumbers,
                                  string _SFXConnectionLost, string _SFXTimeOut, string _SFXResumed, bool offlineCounter,
                                  string networkInterfaceName)
        {
            Delay               = delay;
            MaxPing             = maxPing;
            BgColor             = new Pen(bgColor);
            GoodColor           = new Pen(goodColor);
            NormalColor         = new Pen(normalColor);
            BadColor            = new Pen(badColor);
            RunOnStartup        = runOnStartup;
            TheIPAddress        = address;
            AlarmConnectionLost = alarmConnectionLost;
            AlarmTimeOut        = alarmTimeOut;
            AlarmResumed        = alarmResumed;
            UseNumbers          = useNumbers;
            SFXConnectionLost   = _SFXConnectionLost;
            SFXTimeOut          = _SFXTimeOut;
            SFXResumed          = _SFXResumed;
            OfflineCounter      = offlineCounter;
            NetworkInterfaceName = networkInterfaceName;
        }

        public static void Reset()
        {
            Delay               = 3000;
            MaxPing             = 250;
            OfflineCounter      = true;
            BgColor             = new Pen(Color.FromArgb(70, 0, 0));
            GoodColor           = new Pen(Color.FromArgb(120, 180, 0));
            NormalColor         = new Pen(Color.FromArgb(255, 180, 0));
            BadColor            = new Pen(Color.FromArgb(255, 0, 0));
            RunOnStartup        = false;
            TheIPAddress        = IPAddress.Parse("8.8.8.8"); // google ip
            AlarmConnectionLost = false;
            AlarmTimeOut        = false;
            AlarmResumed        = false;
            UseNumbers          = false;
            SFXConnectionLost   = NONE_SFX;
            SFXTimeOut          = NONE_SFX;
            SFXResumed          = NONE_SFX;
            RunOnStartup        = false;
            NetworkInterfaceName = string.Empty;
        }

        public static void Load()
        {
            if (File.Exists(CONF_FILE_NAME))
            {
                string[] conf = File.ReadAllLines(CONF_FILE_NAME);

                for (int i = 0; i < conf.Length; i++)
                {
                    if (string.IsNullOrWhiteSpace(conf[i]) || conf[i].Trim()[0] == '#')
                        continue;

                    string line = conf[i].Trim();
                    string[] split = line.Split(new char[] { ' ' }, 2);

                    if (split.Length == 2)
                    {
                        switch (split[0])
                        {
                            case nameof(Delay):
                                int.TryParse(split[1], out Delay);
                                break;

                            case nameof(MaxPing):
                                int.TryParse(split[1], out MaxPing);
                                break;

                            case nameof(BgColor):
                                SetPenFromString(ref BgColor, split[1]);
                                break;

                            case nameof(GoodColor):
                                SetPenFromString(ref GoodColor, split[1]);
                                break;

                            case nameof(NormalColor):
                                SetPenFromString(ref NormalColor, split[1]);
                                break;

                            case nameof(BadColor):
                                SetPenFromString(ref BadColor, split[1]);
                                break;

                            case nameof(RunOnStartup):
                                bool.TryParse(split[1], out RunOnStartup);
                                break;

                            case "ipaddress":
                            case nameof(TheIPAddress):
                                if (IPAddress.TryParse(split[1], out IPAddress ip))
                                    TheIPAddress = ip;
                                break;

                            case nameof(AlarmConnectionLost):
                                bool.TryParse(split[1], out AlarmConnectionLost);
                                break;

                            case nameof(AlarmTimeOut):
                                bool.TryParse(split[1], out AlarmTimeOut);
                                break;

                            case nameof(AlarmResumed):
                                bool.TryParse(split[1], out AlarmResumed);
                                break;

                            case nameof(UseNumbers):
                                bool.TryParse(split[1], out UseNumbers);
                                break;

                            case nameof(SFXConnectionLost):
                                SFXConnectionLost = split[1];
                                break;

                            case nameof(SFXTimeOut):
                                SFXTimeOut = split[1];
                                break;

                            case nameof(SFXResumed):
                                SFXResumed = split[1];
                                break;

                            case nameof(OfflineCounter):
                                bool.TryParse(split[1], out OfflineCounter);
                                break;
                                
                            case nameof(NetworkInterfaceName):
                                NetworkInterfaceName = split[1];
                                break;
                        }
                    }
                }
            }
            else
            {
                Reset();
                Save();
            }
        }

        private static void SetPenFromString(ref Pen pen, string str)
        {
            if (str.IndexOf(':') != -1)
            {
                string[] rgb = str.Split(':');
                if (rgb.Length == 3)
                {
                    if (int.TryParse(rgb[0], out int r) && r > -1 && r < 256 &&
                        int.TryParse(rgb[1], out int g) && g > -1 && g < 256 &&
                        int.TryParse(rgb[2], out int b) && b > -1 && b < 256)
                        pen = new Pen(Color.FromArgb(r, g, b));
                }
            }
        }

        public static void Save()
        {
            var sb = new StringBuilder();
            sb.AppendLine("# PingoMeter config file");

            sb.AppendLine($"{nameof(Delay)} {Delay}");
            sb.AppendLine($"{nameof(MaxPing)} {MaxPing}");

            sb.AppendLine($"{nameof(BgColor)} {BgColor.Color.R}:{BgColor.Color.G}:{BgColor.Color.B}");
            sb.AppendLine($"{nameof(GoodColor)} {GoodColor.Color.R}:{GoodColor.Color.G}:{GoodColor.Color.B}");
            sb.AppendLine($"{nameof(NormalColor)} {NormalColor.Color.R}:{NormalColor.Color.G}:{NormalColor.Color.B}");
            sb.AppendLine($"{nameof(BadColor)} {BadColor.Color.R}:{BadColor.Color.G}:{BadColor.Color.B}");

            sb.AppendLine($"{nameof(RunOnStartup)} {RunOnStartup}");

            sb.AppendLine($"{nameof(TheIPAddress)} {TheIPAddress.ToString()}");

            sb.AppendLine($"{nameof(AlarmConnectionLost)} {AlarmConnectionLost}");
            sb.AppendLine($"{nameof(AlarmTimeOut)} {AlarmTimeOut}");
            sb.AppendLine($"{nameof(AlarmResumed)} {AlarmResumed}");
            sb.AppendLine($"{nameof(UseNumbers)} {UseNumbers}");

            sb.AppendLine($"{nameof(SFXConnectionLost)} {SFXConnectionLost}");
            sb.AppendLine($"{nameof(SFXTimeOut)} {SFXTimeOut}");
            sb.AppendLine($"{nameof(SFXResumed)} {SFXResumed}");

            sb.AppendLine($"{nameof(OfflineCounter)} {OfflineCounter}");
            sb.AppendLine($"{nameof(NetworkInterfaceName)} {NetworkInterfaceName}");

            File.WriteAllText(CONF_FILE_NAME, sb.ToString());
        }

    }
}
