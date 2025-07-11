using System;
using System.Diagnostics;
using System.IO;
using System.Media;
using System.Net;
using System.Net.NetworkInformation;
using System.Windows.Forms;

namespace PingoMeter
{
    public partial class Setting : Form
    {
        bool loaded;
        SoundPlayer testPlay;

        public Setting()
        {
            InitializeComponent();
            PopulateNetworkInterfaces();
            SyncFromConfig();
            labelVersion.Text = "Version " + Program.VERSION;
            toolTip1.SetToolTip(numbersModeCheckBox, "Use numbers for the ping instead of a graph.");

            pingTimeoutSFXBtn.Click      += SelectWAV;
            connectionLostSFXBtn.Click   += SelectWAV;
            connectionResumeSFXBtn.Click += SelectWAV;

            pingTimeoutSFXBtn.MouseDown      += (s, e) => ClearSFX(pingTimeoutSFXBtn, e);
            connectionLostSFXBtn.MouseDown   += (s, e) => ClearSFX(connectionLostSFXBtn, e);
            connectionResumeSFXBtn.MouseDown += (s, e) => ClearSFX(connectionResumeSFXBtn, e);

            if (Utils.IsWindows8Next())
            {
                cbStartupRun.Enabled = false;
                cbStartupRun.Visible = false;
                Config.RunOnStartup = false;
            }

            loaded = true;
        }

        private void PopulateNetworkInterfaces()
        {
            networkInterfaceComboBox.Items.Clear();
            networkInterfaceComboBox.Items.Add(string.Empty); // Add empty option for default behavior

            var adapters = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var adapter in adapters)
            {
                if (adapter.OperationalStatus == OperationalStatus.Up)
                {
                    bool hasIPv4 = false;
                    foreach (var uni in adapter.GetIPProperties().UnicastAddresses)
                    {
                        if (uni.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            hasIPv4 = true;
                            break;
                        }
                    }

                    if (hasIPv4)
                    {
                        networkInterfaceComboBox.Items.Add(adapter.Name);
                    }
                }
            }

            networkInterfaceComboBox.SelectedIndex = 0; // Select empty option by default
        }

        private void SyncToConfig(IPAddress address)
        {
            string selectedInterface = networkInterfaceComboBox.SelectedItem?.ToString() ?? string.Empty;
            
            Config.SetAll(
                delay: (int)delay.Value,
                maxPing: (int)maxPing.Value,
                bgColor: setBgColor.BackColor,
                goodColor: setGoodColor.BackColor,
                normalColor: setNormalColor.BackColor,
                badColor: setBadColor.BackColor,
                runOnStartup: cbStartupRun.Checked,
                address: address,
                alarmConnectionLost: alarmConnectionLost.Checked,
                alarmTimeOut: alarmTimeOut.Checked,
                alarmResumed: alarmResumed.Checked,
                useNumbers: numbersModeCheckBox.Checked,
                _SFXConnectionLost: toolTip1.GetToolTip(connectionLostSFXBtn),
                _SFXTimeOut: toolTip1.GetToolTip(pingTimeoutSFXBtn),
                _SFXResumed: toolTip1.GetToolTip(connectionResumeSFXBtn),
                offlineCounter: cbOfflineCounter.Checked,
                networkInterfaceName: selectedInterface);
        }

        private void SyncFromConfig()
        {
            delay.Value   = Config.Delay;
            maxPing.Value = Config.MaxPing;

            setBgColor.BackColor     = Config.BgColor.Color;
            setGoodColor.BackColor   = Config.GoodColor.Color;
            setNormalColor.BackColor = Config.NormalColor.Color;
            setBadColor.BackColor    = Config.BadColor.Color;

            alarmTimeOut.Checked        = Config.AlarmTimeOut;
            alarmConnectionLost.Checked = Config.AlarmConnectionLost;
            alarmResumed.Checked        = Config.AlarmResumed;
            numbersModeCheckBox.Checked = Config.UseNumbers;
            cbStartupRun.Checked        = Config.RunOnStartup;
            cbOfflineCounter.Checked = Config.OfflineCounter;

            //isStartUp.Checked = Config.s_runOnStartup;

            if (Config.TheIPAddress != null)
                ipAddress.Text = Config.TheIPAddress.ToString();

            // Set the selected network interface
            if (!string.IsNullOrEmpty(Config.NetworkInterfaceName))
            {
                for (int i = 0; i < networkInterfaceComboBox.Items.Count; i++)
                {
                    if (networkInterfaceComboBox.Items[i].ToString() == Config.NetworkInterfaceName)
                    {
                        networkInterfaceComboBox.SelectedIndex = i;
                        break;
                    }
                }
            }

            SetSoundInfoForButtom(pingTimeoutSFXBtn,      Config.SFXTimeOut);
            SetSoundInfoForButtom(connectionLostSFXBtn,   Config.SFXConnectionLost);
            SetSoundInfoForButtom(connectionResumeSFXBtn, Config.SFXResumed);
        }

        private void ClearSFX(Button button, MouseEventArgs mouseEvent)
        {
            if (mouseEvent.Button == MouseButtons.Right)
                SetSoundInfoForButtom(button, null);
        }

        private void SetSoundInfoForButtom(Button button, string pathToFile)
        {
            if (string.IsNullOrWhiteSpace(pathToFile) || pathToFile == Config.NONE_SFX || !File.Exists(pathToFile))
            {
                button.Text = Config.NONE_SFX;
                toolTip1.SetToolTip(button, Config.NONE_SFX);
            }
            else
            {
                button.Text = Path.GetFileNameWithoutExtension(pathToFile);
                toolTip1.SetToolTip(button, pathToFile);

                if (loaded)
                {
                    if (testPlay == null)
                        testPlay = new SoundPlayer();

                    if (testPlay.SoundLocation != pathToFile)
                    {
                        testPlay.SoundLocation = pathToFile;
                        try
                        {
                            testPlay.Load();
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show(ex.Message + "\n\nFile: " + pathToFile, "Load sound error",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }

                    if (testPlay.IsLoadCompleted)
                        testPlay.Play();
                }
            }
        }

        private void SelectWAV(object senderAsButton, EventArgs e)
        {
            var dialog = new OpenFileDialog
            {
                CheckFileExists = true,
                DefaultExt = "",
                InitialDirectory = @"C:\Windows\Media\",

                // Filter string you provided is not valid. The filter string must contain a description of the filter,
                // followed by the vertical bar (|) and the filter pattern. The strings for different filtering options
                // must also be separated by the vertical bar.
                // Example: "Text files (*.txt)|*.txt|All files (*.*)|*.*"
                Filter = "WAV file (*.wav)|*.wav",
                Multiselect = false,
                Title = "Select .wav file",
            };

            if (dialog.ShowDialog() == DialogResult.OK)
            {
                SetSoundInfoForButtom((Button)senderAsButton, dialog.FileName);
            }

            dialog.Dispose();
        }

        private void SetBgColor_Click(object sender, EventArgs e)
        {
            if (colorDialog1.ShowDialog() == DialogResult.OK)
            {
                setBgColor.BackColor = colorDialog1.Color;
            }
        }

        private void SetGoodColor_Click(object sender, EventArgs e)
        {
            if (colorDialog1.ShowDialog() == DialogResult.OK)
            {
                setGoodColor.BackColor = colorDialog1.Color;
            }
        }

        private void SetNormalColor_Click(object sender, EventArgs e)
        {
            if (colorDialog1.ShowDialog() == DialogResult.OK)
            {
                setNormalColor.BackColor = colorDialog1.Color;
            }
        }

        private void SetBadColor_Click(object sender, EventArgs e)
        {
            if (colorDialog1.ShowDialog() == DialogResult.OK)
            {
                setBadColor.BackColor = colorDialog1.Color;
            }
        }

        private void Apply_Click(object sender, EventArgs e)
        {
            // check ip address
            if (!IPAddress.TryParse(ipAddress.Text, out IPAddress address))
            {
                MessageBox.Show("IP Address is invalid.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            SyncToConfig(address);
            Config.Save();
            Close();
        }

        private void Cancel_Click(object sender, EventArgs e)
        {
            Close();
        }

        private void Reset_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show(
                "Reset all settings to default?",
                "Reset all?",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question)
                == DialogResult.Yes)
            {
                Config.Reset();
                SyncFromConfig();
            }
        }

        private void LinkLabel1_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            Process.Start("https://github.com/EFLFE/PingoMeter");
        }

        private void numbersModeCheckBox_CheckedChanged(object sender, EventArgs e)
        {
            graphColorsGroupBox.Visible = !numbersModeCheckBox.Checked;
        }
    }
}
