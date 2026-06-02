using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace WazuhEndpointInstaller
{
    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new InstallerForm());
        }
    }

    internal sealed class InstallerForm : Form
    {
        private const string DefaultWazuhManager = "10.2.73.6";

        private readonly TextBox managerTextBox;
        private readonly CheckBox wazuhCheckBox;
        private readonly CheckBox sysmonCheckBox;
        private readonly Button runButton;
        private readonly Button closeButton;
        private readonly TextBox logTextBox;
        private readonly Label statusLabel;

        public InstallerForm()
        {
            Text = "Wazuh + Sysmon Installer";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(720, 520);
            Size = new Size(820, 600);
            Font = new Font("Segoe UI", 9F);

            var mainPanel = new TableLayoutPanel();
            mainPanel.Dock = DockStyle.Fill;
            mainPanel.Padding = new Padding(12);
            mainPanel.ColumnCount = 1;
            mainPanel.RowCount = 6;
            mainPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            mainPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            var titleLabel = new Label();
            titleLabel.AutoSize = true;
            titleLabel.Font = new Font(Font, FontStyle.Bold);
            titleLabel.Text = "Instalacja agenta Wazuh i Sysmon";
            mainPanel.Controls.Add(titleLabel, 0, 0);

            var managerPanel = new TableLayoutPanel();
            managerPanel.AutoSize = true;
            managerPanel.Dock = DockStyle.Top;
            managerPanel.ColumnCount = 2;
            managerPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            managerPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            managerPanel.Margin = new Padding(0, 12, 0, 0);

            var managerLabel = new Label();
            managerLabel.AutoSize = true;
            managerLabel.Anchor = AnchorStyles.Left;
            managerLabel.Text = "Adres IP serwera Wazuh:";
            managerLabel.Margin = new Padding(0, 4, 12, 4);
            managerPanel.Controls.Add(managerLabel, 0, 0);

            managerTextBox = new TextBox();
            managerTextBox.Dock = DockStyle.Fill;
            managerTextBox.Text = DefaultWazuhManager;
            managerPanel.Controls.Add(managerTextBox, 1, 0);
            mainPanel.Controls.Add(managerPanel, 0, 1);

            var checkboxPanel = new FlowLayoutPanel();
            checkboxPanel.AutoSize = true;
            checkboxPanel.Dock = DockStyle.Top;
            checkboxPanel.FlowDirection = FlowDirection.LeftToRight;
            checkboxPanel.Margin = new Padding(0, 12, 0, 0);

            wazuhCheckBox = new CheckBox();
            wazuhCheckBox.AutoSize = true;
            wazuhCheckBox.Checked = true;
            wazuhCheckBox.Text = "Uruchom Install-WazuhAgent.ps1";
            wazuhCheckBox.Margin = new Padding(0, 0, 24, 0);
            checkboxPanel.Controls.Add(wazuhCheckBox);

            sysmonCheckBox = new CheckBox();
            sysmonCheckBox.AutoSize = true;
            sysmonCheckBox.Checked = true;
            sysmonCheckBox.Text = "Uruchom Install-Sysmon.ps1";
            checkboxPanel.Controls.Add(sysmonCheckBox);
            mainPanel.Controls.Add(checkboxPanel, 0, 2);

            var buttonPanel = new FlowLayoutPanel();
            buttonPanel.AutoSize = true;
            buttonPanel.Dock = DockStyle.Top;
            buttonPanel.FlowDirection = FlowDirection.LeftToRight;
            buttonPanel.Margin = new Padding(0, 12, 0, 0);

            runButton = new Button();
            runButton.AutoSize = true;
            runButton.Text = "Uruchom";
            runButton.Click += RunButton_Click;
            buttonPanel.Controls.Add(runButton);

            closeButton = new Button();
            closeButton.AutoSize = true;
            closeButton.Text = "Zamknij";
            closeButton.Margin = new Padding(8, 0, 0, 0);
            closeButton.Click += delegate { Close(); };
            buttonPanel.Controls.Add(closeButton);
            mainPanel.Controls.Add(buttonPanel, 0, 3);

            logTextBox = new TextBox();
            logTextBox.Dock = DockStyle.Fill;
            logTextBox.Multiline = true;
            logTextBox.ReadOnly = true;
            logTextBox.ScrollBars = ScrollBars.Both;
            logTextBox.WordWrap = false;
            logTextBox.Font = new Font("Consolas", 9F);
            logTextBox.Margin = new Padding(0, 12, 0, 0);
            mainPanel.Controls.Add(logTextBox, 0, 4);

            statusLabel = new Label();
            statusLabel.AutoSize = true;
            statusLabel.Text = "Gotowe.";
            statusLabel.Margin = new Padding(0, 8, 0, 0);
            mainPanel.Controls.Add(statusLabel, 0, 5);

            Controls.Add(mainPanel);
        }

        private void RunButton_Click(object sender, EventArgs e)
        {
            var manager = managerTextBox.Text.Trim();
            if (manager.Length == 0)
            {
                MessageBox.Show(this, "Podaj adres IP serwera Wazuh.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (manager.IndexOf('"') >= 0)
            {
                MessageBox.Show(this, "Adres serwera nie moze zawierac cudzyslowu.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            if (!wazuhCheckBox.Checked && !sysmonCheckBox.Checked)
            {
                MessageBox.Show(this, "Zaznacz przynajmniej jeden skrypt do uruchomienia.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            SetUiEnabled(false);
            logTextBox.Clear();
            statusLabel.Text = "Praca w toku...";

            var runWazuh = wazuhCheckBox.Checked;
            var runSysmon = sysmonCheckBox.Checked;

            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    RunSelectedScripts(manager, runWazuh, runSysmon);
                    SetStatus("Zakonczono.");
                }
                catch (Exception ex)
                {
                    AppendLog("");
                    AppendLog("BLAD: " + ex.Message);
                    SetStatus("Blad.");
                    ShowError(ex.Message);
                }
                finally
                {
                    SetUiEnabled(true);
                }
            });
        }

        private void RunSelectedScripts(string manager, bool runWazuh, bool runSysmon)
        {
            var appDir = AppDomain.CurrentDomain.BaseDirectory;
            var wazuhScript = Path.Combine(appDir, "Install-WazuhAgent.ps1");
            var sysmonScript = Path.Combine(appDir, "Install-Sysmon.ps1");

            if (runWazuh)
            {
                RunPowerShellScript(wazuhScript, "-WazuhManager " + Quote(manager));
            }

            if (runSysmon)
            {
                RunPowerShellScript(sysmonScript, "");
            }
        }

        private void RunPowerShellScript(string scriptPath, string extraArguments)
        {
            if (!File.Exists(scriptPath))
            {
                throw new FileNotFoundException("Nie znaleziono skryptu: " + scriptPath, scriptPath);
            }

            AppendLog("============================================================");
            AppendLog("Uruchamiam: " + Path.GetFileName(scriptPath));
            AppendLog("Sciezka: " + scriptPath);
            AppendLog("");

            var powershellPath = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            var arguments = "-NoProfile -ExecutionPolicy Bypass -File " + Quote(scriptPath);
            if (!String.IsNullOrWhiteSpace(extraArguments))
            {
                arguments += " " + extraArguments;
            }

            var psi = new ProcessStartInfo();
            psi.FileName = powershellPath;
            psi.Arguments = arguments;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.StandardOutputEncoding = Encoding.UTF8;
            psi.StandardErrorEncoding = Encoding.UTF8;

            using (var process = new Process())
            {
                process.StartInfo = psi;
                process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e)
                {
                    if (e.Data != null)
                    {
                        AppendLog(e.Data);
                    }
                };
                process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e)
                {
                    if (e.Data != null)
                    {
                        AppendLog(e.Data);
                    }
                };

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                process.WaitForExit();

                AppendLog("");
                AppendLog(Path.GetFileName(scriptPath) + " zakonczony kodem: " + process.ExitCode);

                if (process.ExitCode != 0)
                {
                    throw new InvalidOperationException(Path.GetFileName(scriptPath) + " zakonczyl sie bledem. Kod: " + process.ExitCode);
                }
            }
        }

        private static string Quote(string value)
        {
            return "\"" + value.Replace("\"", "\\\"") + "\"";
        }

        private void AppendLog(string text)
        {
            if (logTextBox.InvokeRequired)
            {
                logTextBox.BeginInvoke(new Action<string>(AppendLog), text);
                return;
            }

            logTextBox.AppendText(text + Environment.NewLine);
        }

        private void SetStatus(string text)
        {
            if (statusLabel.InvokeRequired)
            {
                statusLabel.BeginInvoke(new Action<string>(SetStatus), text);
                return;
            }

            statusLabel.Text = text;
        }

        private void ShowError(string message)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action<string>(ShowError), message);
                return;
            }

            MessageBox.Show(this, message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }

        private void SetUiEnabled(bool enabled)
        {
            if (InvokeRequired)
            {
                BeginInvoke(new Action<bool>(SetUiEnabled), enabled);
                return;
            }

            managerTextBox.Enabled = enabled;
            wazuhCheckBox.Enabled = enabled;
            sysmonCheckBox.Enabled = enabled;
            runButton.Enabled = enabled;
            closeButton.Enabled = enabled;
        }
    }
}
