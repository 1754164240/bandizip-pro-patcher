// Bandizip 离线注册补丁器
// 一键把 Bandizip.exe 的 edition 判定改为 Professional，并支持还原。
// 编译:
//   csc /nologo /target:winexe /platform:x64 /codepage:65001
//       /win32manifest:app.manifest /optimize+ /out:BandizipPatcher.exe BandizipPatcher.cs

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

namespace BzPatcher
{
    // ==================================================================
    // 补丁核心
    // ==================================================================
    internal static class Bz
    {
        public const string OrigSha = "2d733a26500a8cff7db04291c396b3d48e9d7275753e2a06bf3564c9f9591dc8";
        public const string PatchSha = "e0d8170b17822ab611e87e7c021b83e22eae6564c75b9e2bf8cfccdb4b53d6aa";

        // Bandizip 7.47.0.1 (build 71912)
        public const int FuncRva = 0x1316C0;   // edition 映射函数
        public const int GetAppRva = 0xCF570;  // app 单例 getter
        public const int AssignRva = 0x18F50;  // std::wstring::assign
        public const int OkStrRva = 0x2A6B40;  // L"ok"
        public const int ProStrRva = 0x2A6B38; // L"PRO"

        public static readonly byte[] Signature = new byte[]
        {
            0x48, 0x89, 0x5C, 0x24, 0x08,
            0x48, 0x89, 0x74, 0x24, 0x10,
            0x57, 0x48, 0x83, 0xEC, 0x20,
            0x48, 0x8B, 0xF1
        };

        public static string Sha256(byte[] b)
        {
            using (SHA256 h = SHA256.Create())
                return ToHex(h.ComputeHash(b));
        }

        public static string Sha256File(string path)
        {
            using (FileStream fs = File.OpenRead(path))
            using (SHA256 h = SHA256.Create())
                return ToHex(h.ComputeHash(fs));
        }

        static string ToHex(byte[] d)
        {
            StringBuilder sb = new StringBuilder(d.Length * 2);
            for (int i = 0; i < d.Length; i++) sb.Append(d[i].ToString("x2"));
            return sb.ToString();
        }

        static uint U32(byte[] b, int off) { return BitConverter.ToUInt32(b, off); }
        static ushort U16(byte[] b, int off) { return BitConverter.ToUInt16(b, off); }

        public static long RvaToOffset(byte[] pe, uint rva)
        {
            int e = (int)U32(pe, 0x3C);
            int nsec = U16(pe, e + 6);
            int optSize = U16(pe, e + 20);
            int st = e + 24 + optSize;
            for (int i = 0; i < nsec; i++)
            {
                int o = st + i * 40;
                uint vs = U32(pe, o + 8);
                uint va = U32(pe, o + 12);
                uint rs = U32(pe, o + 16);
                uint raw = U32(pe, o + 20);
                uint size = Math.Max(vs, rs);
                if (rva >= va && rva < va + size) return (long)raw + (rva - va);
            }
            throw new Exception("RVA 0x" + rva.ToString("X") + " 不在任何 PE 节内");
        }

        public static bool Matches(byte[] data, long off, byte[] pattern, int len)
        {
            if (off < 0 || off + len > data.Length) return false;
            for (int i = 0; i < len; i++)
                if (data[off + i] != pattern[i]) return false;
            return true;
        }

        // 78 字节补丁代码：
        //   push rbx / sub rsp,0x20 / mov rbx,rcx
        //   app = getApp(); assign(app+0x60, L"ok", 2)
        //   app = getApp(); assign(app+0x28, L"PRO", 3)
        //   [rbx+0x120] = 0x3D4 (=Professional) / add rsp,0x20 / pop rbx / ret
        public static byte[] BuildCode()
        {
            List<byte> c = new List<byte>(96);
            c.Add(0x53);                                       // push rbx
            c.AddRange(new byte[] { 0x48, 0x83, 0xEC, 0x20 }); // sub rsp,0x20
            c.AddRange(new byte[] { 0x48, 0x89, 0xCB });       // mov rbx,rcx

            AddCall(c, FuncRva, GetAppRva);
            c.AddRange(new byte[] { 0x48, 0x8D, 0x48, 0x60 }); // lea rcx,[rax+0x60]
            AddLea(c, FuncRva, OkStrRva);
            c.AddRange(new byte[] { 0x41, 0xB8, 0x02, 0, 0, 0 });
            AddCall(c, FuncRva, AssignRva);

            AddCall(c, FuncRva, GetAppRva);
            c.AddRange(new byte[] { 0x48, 0x8D, 0x48, 0x28 }); // lea rcx,[rax+0x28]
            AddLea(c, FuncRva, ProStrRva);
            c.AddRange(new byte[] { 0x41, 0xB8, 0x03, 0, 0, 0 });
            AddCall(c, FuncRva, AssignRva);

            c.AddRange(new byte[] { 0xC7, 0x83, 0x20, 0x01, 0x00, 0x00, 0xD4, 0x03, 0x00, 0x00 });
            c.AddRange(new byte[] { 0x48, 0x83, 0xC4, 0x20 }); // add rsp,0x20
            c.Add(0x5B);                                       // pop rbx
            c.Add(0xC3);                                       // ret
            return c.ToArray();
        }

        static void AddCall(List<byte> c, int funcRva, int targetRva)
        {
            int start = c.Count;
            c.AddRange(new byte[] { 0xE8, 0, 0, 0, 0 });
            WriteRel(c, start + 1, funcRva + start + 5, targetRva);
        }

        static void AddLea(List<byte> c, int funcRva, int targetRva)
        {
            int start = c.Count;
            c.AddRange(new byte[] { 0x48, 0x8D, 0x15, 0, 0, 0, 0 });
            WriteRel(c, start + 3, funcRva + start + 7, targetRva);
        }

        static void WriteRel(List<byte> c, int field, int nextRva, int targetRva)
        {
            byte[] v = BitConverter.GetBytes(targetRva - nextRva);
            c[field] = v[0]; c[field + 1] = v[1]; c[field + 2] = v[2]; c[field + 3] = v[3];
        }
    }

    // ==================================================================
    // 安装目录定位
    // ==================================================================
    internal static class Locator
    {
        public static string Find()
        {
            List<string> cand = new List<string>();

            Reg(cand, RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Bandizip", "ProgramFolder");
            Reg(cand, RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Bandizip", "ProgramFolder");
            Reg(cand, RegistryHive.CurrentUser, RegistryView.Default, @"Software\Bandizip", "ProgramFolder");
            AppPath(cand);
            Running(cand);

            Add(cand, Environment.SpecialFolder.ProgramFiles, "Bandizip");
            Add(cand, Environment.SpecialFolder.ProgramFilesX86, "Bandizip");
            Add(cand, Environment.SpecialFolder.LocalApplicationData, @"Programs\Bandizip");

            foreach (string d in cand)
            {
                if (string.IsNullOrEmpty(d)) continue;
                string dir = d.Trim().TrimEnd('\\', '/');
                try
                {
                    if (File.Exists(Path.Combine(dir, "Bandizip.exe"))) return dir;
                }
                catch { }
            }
            return null;
        }

        static void Add(List<string> cand, Environment.SpecialFolder sf, string sub)
        {
            try { cand.Add(Path.Combine(Environment.GetFolderPath(sf), sub)); }
            catch { }
        }

        static void Reg(List<string> cand, RegistryHive hive, RegistryView view, string sub, string name)
        {
            try
            {
                using (RegistryKey root = RegistryKey.OpenBaseKey(hive, view))
                using (RegistryKey k = root.OpenSubKey(sub))
                {
                    if (k == null) return;
                    object v = k.GetValue(name);
                    if (v != null) cand.Add(Convert.ToString(v));
                }
            }
            catch { }
        }

        static void AppPath(List<string> cand)
        {
            try
            {
                using (RegistryKey k = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Bandizip.exe"))
                {
                    if (k == null) return;
                    object v = k.GetValue(null);
                    if (v != null) cand.Add(Path.GetDirectoryName(Convert.ToString(v)));
                }
            }
            catch { }
        }

        static void Running(List<string> cand)
        {
            try
            {
                foreach (Process p in Process.GetProcessesByName("Bandizip"))
                {
                    try
                    {
                        string path = p.MainModule.FileName;
                        if (!string.IsNullOrEmpty(path)) cand.Add(Path.GetDirectoryName(path));
                    }
                    catch { }
                    finally { p.Dispose(); }
                }
            }
            catch { }
        }
    }

    // ==================================================================
    // 补丁引擎
    // ==================================================================
    internal enum BzState { Missing, Original, Patched, Unknown }

    internal static class Engine
    {
        public static string ExePath(string dir) { return Path.Combine(dir, "Bandizip.exe"); }

        public static BzState Detect(string dir, out string sha, out string ver)
        {
            sha = "";
            ver = "";
            string exe = ExePath(dir);
            if (!File.Exists(exe)) return BzState.Missing;
            try
            {
                ver = FileVersionInfo.GetVersionInfo(exe).FileVersion;
                sha = Bz.Sha256File(exe);
            }
            catch { return BzState.Unknown; }

            if (sha == Bz.PatchSha) return BzState.Patched;
            if (sha == Bz.OrigSha) return BzState.Original;

            try
            {
                byte[] data = File.ReadAllBytes(exe);
                long off = Bz.RvaToOffset(data, Bz.FuncRva);
                if (ver != null && ver.StartsWith("7.47") &&
                    Bz.Matches(data, off, Bz.Signature, Bz.Signature.Length))
                    return BzState.Original;
            }
            catch { }
            return BzState.Unknown;
        }

        public static void KillRunning(Action<string> log)
        {
            foreach (Process p in Process.GetProcessesByName("Bandizip"))
            {
                try
                {
                    log("结束正在运行的 Bandizip (PID " + p.Id + ")");
                    p.Kill();
                    p.WaitForExit(4000);
                }
                catch { }
                finally { p.Dispose(); }
            }
        }

        public static string Patch(string dir, bool disableUpdate, Action<string> log)
        {
            string exe = ExePath(dir);
            string bak = exe + ".bak";
            if (!File.Exists(exe)) throw new Exception("找不到文件：\n" + exe);

            string sha, ver;
            BzState st = Detect(dir, out sha, out ver);
            if (st == BzState.Patched) return "当前已经是破解版（Professional），无需重复打补丁。";
            if (st == BzState.Missing) throw new Exception("该目录下没有 Bandizip.exe。");
            if (st == BzState.Unknown)
                throw new Exception("无法识别该版本（FileVersion=" + ver + "）。\n本补丁只支持 7.47.0.1 (build 71912)。");

            log("目标: " + exe);
            log("版本: " + ver);
            log("SHA256: " + sha);

            KillRunning(log);

            byte[] data = File.ReadAllBytes(exe);
            long off = Bz.RvaToOffset(data, Bz.FuncRva);
            if (!Bz.Matches(data, off, Bz.Signature, Bz.Signature.Length))
                throw new Exception("目标函数特征不匹配（可能已被其它工具修改），已中止。");

            bool needBackup = true;
            if (File.Exists(bak))
            {
                string bakSha = Bz.Sha256File(bak);
                log("发现已有备份: " + bak);
                log("备份 SHA256: " + bakSha);
                if (bakSha == Bz.OrigSha || bakSha == sha) needBackup = false;
            }
            if (needBackup)
            {
                File.Copy(exe, bak, true);
                log("已创建备份: " + bak);
            }

            byte[] code = Bz.BuildCode();
            Array.Copy(code, 0, data, off, code.Length);
            File.WriteAllBytes(exe, data);
            log("已写入 " + code.Length + " 字节补丁");

            string newSha = Bz.Sha256File(exe);
            log("新 SHA256: " + newSha);
            if (newSha != Bz.PatchSha) throw new Exception("写入后校验失败，请用备份还原：\n" + bak);

            if (disableUpdate)
            {
                try
                {
                    using (RegistryKey k = Registry.CurrentUser.CreateSubKey(@"Software\Bandizip"))
                        if (k != null) k.SetValue("update", 0, RegistryValueKind.DWord);
                    log("已关闭自动更新 (HKCU\\Software\\Bandizip\\update=0)");
                }
                catch (Exception ex) { log("关闭自动更新失败: " + ex.Message); }
            }

            return "补丁完成。启动 Bandizip 后标题应显示 Bandizip (Professional)。";
        }

        public static string Restore(string dir, Action<string> log)
        {
            string exe = ExePath(dir);
            string bak = exe + ".bak";
            if (!File.Exists(exe)) throw new Exception("找不到文件：\n" + exe);
            if (!File.Exists(bak)) throw new Exception("没有备份文件：\n" + bak);

            KillRunning(log);
            File.Copy(bak, exe, true);
            string sha = Bz.Sha256File(exe);
            log("已用备份覆盖，SHA256: " + sha);
            if (sha != Bz.OrigSha) return "已还原，但哈希与官方 7.47.0.1 不一致（备份可能不是原始文件）。";
            return "已还原为官方原版。";
        }

        public static void Startup(string exe)
        {
            try { Process.Start(exe); } catch { }
        }
    }

    // ==================================================================
    // 界面
    // ==================================================================
    internal sealed class MainForm : Form
    {
        readonly string _initialDir;
        readonly TextBox _path = new TextBox();
        readonly Label _state = new Label();
        readonly TextBox _log = new TextBox();
        readonly Button _btnPatch = new Button();
        readonly Button _btnRestore = new Button();
        readonly CheckBox _chkNoUpdate = new CheckBox();

        public MainForm(string initialDir)
        {
            _initialDir = initialDir;
            Text = "Bandizip 离线注册补丁器  v1.1  (适用于 7.47.0.1)";
            ClientSize = new Size(640, 500);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9f);
            AutoScaleMode = AutoScaleMode.None;
            AllowDrop = true;

            Label lb1 = new Label();
            lb1.Text = "安装目录：";
            lb1.SetBounds(14, 20, 76, 22);
            Controls.Add(lb1);

            _path.SetBounds(94, 17, 396, 26);
            _path.ReadOnly = true;
            Controls.Add(_path);

            Button browse = new Button();
            browse.Text = "浏览…";
            browse.SetBounds(498, 16, 128, 28);
            browse.Click += delegate { Browse(); };
            Controls.Add(browse);

            GroupBox gb = new GroupBox();
            gb.Text = "状态";
            gb.SetBounds(14, 56, 612, 84);
            Controls.Add(gb);

            _state.SetBounds(14, 26, 584, 48);
            _state.Text = "正在检测…";
            gb.Controls.Add(_state);

            Button detect = new Button();
            detect.Text = "重新自动检测";
            detect.SetBounds(14, 150, 132, 30);
            detect.Click += delegate { AutoDetect(true); };
            Controls.Add(detect);

            _chkNoUpdate.Text = "同时关闭自动更新（防止补丁被升级覆盖）";
            _chkNoUpdate.Checked = true;
            _chkNoUpdate.SetBounds(158, 154, 400, 24);
            Controls.Add(_chkNoUpdate);

            _btnPatch.Text = "一键打补丁";
            _btnPatch.SetBounds(14, 192, 612, 48);
            _btnPatch.Font = new Font("Microsoft YaHei UI", 12f, FontStyle.Bold);
            _btnPatch.BackColor = Color.FromArgb(219, 238, 255);
            _btnPatch.Click += delegate { DoPatch(); };
            Controls.Add(_btnPatch);

            _btnRestore.Text = "还原官方原版（使用 .bak 备份）";
            _btnRestore.SetBounds(14, 248, 612, 32);
            _btnRestore.Click += delegate { DoRestore(); };
            Controls.Add(_btnRestore);

            _log.SetBounds(14, 292, 612, 194);
            _log.Multiline = true;
            _log.ScrollBars = ScrollBars.Vertical;
            _log.ReadOnly = true;
            _log.BackColor = Color.White;
            _log.Font = new Font("Consolas", 9f);
            Controls.Add(_log);

            DragEnter += delegate (object s, DragEventArgs e)
            {
                if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
            };
            DragDrop += delegate (object s, DragEventArgs e)
            {
                string[] files = e.Data.GetData(DataFormats.FileDrop) as string[];
                if (files == null || files.Length == 0) return;
                string p = files[0];
                string dir = Directory.Exists(p) ? p : Path.GetDirectoryName(p);
                if (dir != null && File.Exists(Path.Combine(dir, "Bandizip.exe")))
                {
                    _path.Text = dir;
                    Log("使用拖入的目录: " + dir);
                    Refresh1();
                }
                else Log("拖入的路径里没有 Bandizip.exe: " + p);
            };

            Load += delegate
            {
                if (!string.IsNullOrEmpty(_initialDir) && Directory.Exists(_initialDir))
                {
                    _path.Text = _initialDir;
                    Log("使用指定目录: " + _initialDir);
                    Refresh1();
                }
                else AutoDetect(false);
            };
        }

        void Log(string s)
        {
            _log.AppendText("[" + DateTime.Now.ToString("HH:mm:ss") + "] " + s + Environment.NewLine);
            _log.SelectionStart = _log.TextLength;
            _log.ScrollToCaret();
        }

        void Browse()
        {
            using (FolderBrowserDialog d = new FolderBrowserDialog())
            {
                d.Description = "选择 Bandizip 安装目录（包含 Bandizip.exe）";
                if (Directory.Exists(_path.Text)) d.SelectedPath = _path.Text;
                if (d.ShowDialog(this) == DialogResult.OK)
                {
                    _path.Text = d.SelectedPath;
                    Log("已选择: " + d.SelectedPath);
                    Refresh1();
                }
            }
        }

        void AutoDetect(bool verbose)
        {
            string dir = Locator.Find();
            if (dir == null)
            {
                _path.Text = "";
                _state.ForeColor = Color.Firebrick;
                _state.Text = "未检测到 Bandizip 安装目录。\r\n请点「浏览…」手动指定，或把安装文件夹拖进窗口。";
                _btnPatch.Enabled = false;
                _btnRestore.Enabled = false;
                if (verbose) Log("自动检测失败。");
                return;
            }
            _path.Text = dir;
            if (verbose) Log("检测到: " + dir);
            Refresh1();
        }

        void Refresh1()
        {
            string dir = _path.Text;
            _btnPatch.Enabled = false;
            _btnRestore.Enabled = false;
            if (string.IsNullOrEmpty(dir)) return;

            string sha, ver;
            BzState st = Engine.Detect(dir, out sha, out ver);
            string shortSha = sha.Length >= 16 ? sha.Substring(0, 16) + "…" : sha;

            if (st == BzState.Missing)
            {
                _state.ForeColor = Color.Firebrick;
                _state.Text = "该目录下没有 Bandizip.exe。";
                return;
            }
            if (st == BzState.Original)
            {
                _state.ForeColor = Color.SeaGreen;
                _state.Text = "版本 " + ver + "    状态：官方原版，可以打补丁\r\nSHA256: " + shortSha;
                _btnPatch.Enabled = true;
                _btnRestore.Enabled = File.Exists(Engine.ExePath(dir) + ".bak");
            }
            else if (st == BzState.Patched)
            {
                _state.ForeColor = Color.RoyalBlue;
                _state.Text = "版本 " + ver + "    状态：已破解（Professional）\r\nSHA256: " + shortSha;
                _btnRestore.Enabled = File.Exists(Engine.ExePath(dir) + ".bak");
            }
            else
            {
                _state.ForeColor = Color.DarkOrange;
                _state.Text = "版本 " + ver + "    状态：未识别的版本 / 文件，本工具只支持 7.47.0.1\r\nSHA256: " + shortSha;
            }
        }

        void DoPatch()
        {
            string dir = _path.Text;
            if (string.IsNullOrEmpty(dir)) return;
            if (MessageBox.Show(this,
                "将把下面这个文件改为 Professional 版：\r\n\r\n" + Engine.ExePath(dir) +
                "\r\n\r\n会自动结束正在运行的 Bandizip，并生成 .bak 备份。继续？",
                "确认打补丁", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) != DialogResult.OK)
                return;

            _btnPatch.Enabled = false;
            Cursor = Cursors.WaitCursor;
            try
            {
                string msg = Engine.Patch(dir, _chkNoUpdate.Checked, Log);
                Log(msg);
                MessageBox.Show(this, msg, "完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
                Engine.Startup(Engine.ExePath(dir));
            }
            catch (Exception ex)
            {
                Log("失败: " + ex.Message);
                MessageBox.Show(this, ex.Message, "失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                Cursor = Cursors.Default;
                Refresh1();
            }
        }

        void DoRestore()
        {
            string dir = _path.Text;
            if (string.IsNullOrEmpty(dir)) return;
            if (MessageBox.Show(this, "将用 .bak 备份覆盖当前的 Bandizip.exe，继续？",
                "确认还原", MessageBoxButtons.OKCancel, MessageBoxIcon.Warning) != DialogResult.OK)
                return;

            _btnRestore.Enabled = false;
            Cursor = Cursors.WaitCursor;
            try
            {
                string msg = Engine.Restore(dir, Log);
                Log(msg);
                MessageBox.Show(this, msg, "完成", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                Log("失败: " + ex.Message);
                MessageBox.Show(this, ex.Message, "失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                Cursor = Cursors.Default;
                Refresh1();
            }
        }
    }

    // ==================================================================
    // 入口
    // ==================================================================
    internal static class Native
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode, EntryPoint = "MessageBoxTimeoutW")]
        static extern int MessageBoxTimeoutW(IntPtr hWnd, string text, string caption,
                                             uint type, ushort lang, uint ms);

        public static void TimedBox(IntPtr h, string text, string caption, uint type, uint ms)
        {
            try { MessageBoxTimeoutW(h, text, caption, type, 0, ms); }
            catch
            {
                MessageBox.Show(text, caption, MessageBoxButtons.OK,
                    type == 0x10 ? MessageBoxIcon.Error : MessageBoxIcon.Information);
            }
        }
    }

    internal static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            bool silent = false, quiet = false, restore = false;
            string dir = null;
            foreach (string a in args)
            {
                string s = a.ToLowerInvariant();
                if (s == "/s" || s == "/silent" || s == "-silent") silent = true;
                else if (s == "/q" || s == "/quiet" || s == "-quiet") { silent = true; quiet = true; }
                else if (s == "/r" || s == "/restore" || s == "-restore") restore = true;
                else if (s == "/p" || s == "/patch" || s == "-patch") { }
                else if (Directory.Exists(a)) dir = a;
                else if (File.Exists(a)) dir = Path.GetDirectoryName(a);
            }

            if (silent)
            {
                string ok = "", err = "";
                try
                {
                    if (dir == null) dir = Locator.Find();
                    if (dir == null) throw new Exception("未检测到 Bandizip 安装目录");
                    List<string> lines = new List<string>();
                    Action<string> log = delegate (string s) { lines.Add(s); };
                    string msg = restore ? Engine.Restore(dir, log) : Engine.Patch(dir, true, log);
                    ok = msg + "\r\n\r\n" + string.Join("\r\n", lines.ToArray());
                }
                catch (Exception ex) { err = ex.Message; }

                if (!quiet)
                {
                    if (err.Length > 0) Native.TimedBox(IntPtr.Zero, err, "Bandizip 补丁器 - 失败", 0x10, 60000);
                    else Native.TimedBox(IntPtr.Zero, ok, "Bandizip 补丁器", 0x40, 60000);
                }
                Environment.ExitCode = err.Length > 0 ? 1 : 0;
                return;
            }

            Application.Run(new MainForm(dir));
        }
    }
}
