// Healthcare Threat Monitor: the Windows collector's core.
//
// Windows PowerShell compiles this file each time the collector runs (Add-Type), so it is written for
// C# 5 and the .NET Framework 4.5 that every supported Windows computer already has. Nothing is downloaded.
//
// It turns Windows events into the platform's format, keeping only the fields the platform reads, signs each
// batch with this group's secret, and sends it over HTTPS. When config.json carries the installation's own
// root certificate, the computer trusts that certificate authority for this connection only, and nothing else.
// The position reached in each event log is saved after every batch the platform has stored.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace HealthcareThreatMonitor
{
    public sealed class CollectorException : Exception
    {
        public CollectorException(string message) : base(message) { }
    }

    // A small JSON reader and writer, so nothing beyond the .NET Framework is needed.
    public static class Json
    {
        public static object Parse(string text)
        {
            int i = 0;
            object value = ReadValue(text, ref i);
            SkipSpace(text, ref i);
            if (i != text.Length) throw new CollectorException("Unexpected text after JSON value");
            return value;
        }

        static void SkipSpace(string s, ref int i)
        {
            while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
        }

        static object ReadValue(string s, ref int i)
        {
            SkipSpace(s, ref i);
            if (i >= s.Length) throw new CollectorException("JSON ended early");
            char c = s[i];
            if (c == '{')
            {
                var obj = new Dictionary<string, object>(StringComparer.Ordinal);
                i++;
                SkipSpace(s, ref i);
                if (i < s.Length && s[i] == '}') { i++; return obj; }
                while (true)
                {
                    SkipSpace(s, ref i);
                    string key = ReadString(s, ref i);
                    SkipSpace(s, ref i);
                    Expect(s, ref i, ':');
                    obj[key] = ReadValue(s, ref i);
                    SkipSpace(s, ref i);
                    if (i < s.Length && s[i] == ',') { i++; continue; }
                    Expect(s, ref i, '}');
                    return obj;
                }
            }
            if (c == '[')
            {
                var list = new List<object>();
                i++;
                SkipSpace(s, ref i);
                if (i < s.Length && s[i] == ']') { i++; return list; }
                while (true)
                {
                    list.Add(ReadValue(s, ref i));
                    SkipSpace(s, ref i);
                    if (i < s.Length && s[i] == ',') { i++; continue; }
                    Expect(s, ref i, ']');
                    return list;
                }
            }
            if (c == '"') return ReadString(s, ref i);
            if (Matches(s, i, "true")) { i += 4; return true; }
            if (Matches(s, i, "false")) { i += 5; return false; }
            if (Matches(s, i, "null")) { i += 4; return null; }
            int start = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            if (start == i) throw new CollectorException("Unexpected character in JSON");
            return double.Parse(s.Substring(start, i - start), NumberStyles.Float, CultureInfo.InvariantCulture);
        }

        static bool Matches(string s, int i, string word)
        {
            return string.CompareOrdinal(s, i, word, 0, word.Length) == 0;
        }

        static void Expect(string s, ref int i, char c)
        {
            if (i >= s.Length || s[i] != c) throw new CollectorException("Expected " + c + " in JSON");
            i++;
        }

        static string ReadString(string s, ref int i)
        {
            Expect(s, ref i, '"');
            var sb = new StringBuilder();
            while (i < s.Length)
            {
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                if (i >= s.Length) break;
                char e = s[i++];
                switch (e)
                {
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'u':
                        if (i + 4 > s.Length) throw new CollectorException("Bad escape in JSON");
                        sb.Append((char)int.Parse(s.Substring(i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                        i += 4;
                        break;
                    default: sb.Append(e); break;
                }
            }
            throw new CollectorException("Unterminated string in JSON");
        }

        public static string Write(object value)
        {
            var sb = new StringBuilder();
            WriteValue(sb, value);
            return sb.ToString();
        }

        static void WriteValue(StringBuilder sb, object value)
        {
            if (value == null) { sb.Append("null"); return; }
            var text = value as string;
            if (text != null) { WriteString(sb, text); return; }
            if (value is bool) { sb.Append((bool)value ? "true" : "false"); return; }
            if (value is int || value is long) { sb.Append(Convert.ToInt64(value).ToString(CultureInfo.InvariantCulture)); return; }
            if (value is double) { sb.Append(((double)value).ToString("R", CultureInfo.InvariantCulture)); return; }
            var dict = value as IDictionary<string, object>;
            if (dict != null)
            {
                sb.Append('{');
                bool first = true;
                foreach (var pair in dict)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteString(sb, pair.Key);
                    sb.Append(':');
                    WriteValue(sb, pair.Value);
                }
                sb.Append('}');
                return;
            }
            var list = value as IEnumerable;
            if (list != null)
            {
                sb.Append('[');
                bool first = true;
                foreach (object item in list)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    WriteValue(sb, item);
                }
                sb.Append(']');
                return;
            }
            WriteString(sb, Convert.ToString(value, CultureInfo.InvariantCulture));
        }

        static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }
    }

    public sealed class Config
    {
        public string ApiUrl;
        public string CollectorId;
        public string Secret;
        public string RootCertificate;
        public int IntervalMinutes = 1;

        public static Config Load(string path)
        {
            var o = Json.Parse(File.ReadAllText(path, Encoding.UTF8)) as Dictionary<string, object>;
            if (o == null) throw new CollectorException("config.json is not a JSON object");
            var c = new Config();
            c.ApiUrl = Text(o, "api_url");
            c.CollectorId = Text(o, "collector_id");
            c.Secret = Text(o, "secret");
            c.RootCertificate = Text(o, "root_certificate");
            object minutes;
            if (o.TryGetValue("interval_minutes", out minutes) && minutes is double) c.IntervalMinutes = Math.Max(1, (int)(double)minutes);
            if (string.IsNullOrEmpty(c.ApiUrl) || string.IsNullOrEmpty(c.CollectorId) || string.IsNullOrEmpty(c.Secret))
                throw new CollectorException("config.json must give api_url, collector_id and secret");
            Uri uri;
            if (!Uri.TryCreate(c.ApiUrl, UriKind.Absolute, out uri)) throw new CollectorException("api_url is not a web address");
            // Plain http is only for a test receiver on this same computer. Everything else must be encrypted.
            if (uri.Scheme != "https" && !(uri.Scheme == "http" && uri.IsLoopback))
                throw new CollectorException("api_url must start with https://");
            return c;
        }

        static string Text(Dictionary<string, object> o, string key)
        {
            object v;
            return o.TryGetValue(key, out v) && v is string ? (string)v : null;
        }
    }

    // Turns one event, as Windows writes it in XML, into the record the platform's Windows reader expects.
    public static class EventConverter
    {
        const string Ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        const int MaxValue = 2000;

        // Only these fields are sent. Everything else in an event stays on the computer.
        static readonly HashSet<string> Keep = new HashSet<string>(StringComparer.Ordinal)
        {
            "TargetUserName", "TargetDomainName", "SubjectUserName", "SubjectDomainName", "IpAddress", "IpPort",
            "LogonType", "FailureReason", "Status", "SubStatus", "WorkstationName", "ProcessName",
            "ServiceName", "ImageName", "StartType", "AccountName", "param1", "param2",
            "NewProcessName", "ParentProcessName", "CommandLine", "TaskName", "MemberName", "PrivilegeList",
        };

        public static Dictionary<string, object> Convert(string xml)
        {
            var doc = new XmlDocument();
            doc.XmlResolver = null;
            using (var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }))
            {
                doc.Load(reader);
            }
            var ns = new XmlNamespaceManager(doc.NameTable);
            ns.AddNamespace("e", Ns);
            var system = doc.SelectSingleNode("/e:Event/e:System", ns);
            if (system == null) throw new CollectorException("Not a Windows event");
            string recordId = Value(system, "e:EventRecordID", ns);
            string eventId = Value(system, "e:EventID", ns);
            var created = system.SelectSingleNode("e:TimeCreated/@SystemTime", ns);
            if (string.IsNullOrEmpty(recordId) || string.IsNullOrEmpty(eventId) || created == null)
                throw new CollectorException("Event without a record number, ID or time");

            var data = new Dictionary<string, object>(StringComparer.Ordinal);
            var fields = doc.SelectNodes("/e:Event/e:EventData/e:Data", ns);
            int unnamed = 0;
            foreach (XmlNode d in fields)
            {
                var name = d.Attributes != null && d.Attributes["Name"] != null ? d.Attributes["Name"].Value : "param" + (++unnamed);
                Add(data, name, d.InnerText);
            }
            // Some events, such as the security log being cleared, keep their fields under UserData instead.
            var user = doc.SelectSingleNode("/e:Event/*[local-name()='UserData']/*", ns);
            if (user != null)
            {
                foreach (XmlNode d in user.ChildNodes)
                {
                    if (d.NodeType == XmlNodeType.Element) Add(data, d.LocalName, d.InnerText);
                }
            }

            var record = new Dictionary<string, object>(StringComparer.Ordinal);
            record["RecordId"] = recordId;
            record["Computer"] = Value(system, "e:Computer", ns);
            record["TimeCreated"] = Time(created.Value);
            record["EventID"] = long.Parse(eventId, CultureInfo.InvariantCulture);
            record["Channel"] = Value(system, "e:Channel", ns);
            record["Data"] = data;
            return record;
        }

        static void Add(Dictionary<string, object> data, string name, string value)
        {
            if (!Keep.Contains(name) || value == null) return;
            data[name] = value.Length > MaxValue ? value.Substring(0, MaxValue) : value;
        }

        static string Value(XmlNode node, string path, XmlNamespaceManager ns)
        {
            var n = node.SelectSingleNode(path, ns);
            return n == null ? null : n.InnerText.Trim();
        }

        // Windows writes seven decimal places. The platform keeps milliseconds, in UTC.
        public static string Time(string systemTime)
        {
            DateTime t;
            if (!DateTime.TryParse(systemTime, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out t))
                throw new CollectorException("Unreadable event time: " + systemTime);
            return t.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
        }
    }

    // The same signature the platform's other collectors use. See web/lib/signing.ts.
    public static class Signer
    {
        public static string Hex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes) sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        public static string Canonical(string timestamp, string method, string path, byte[] body)
        {
            using (var sha = SHA256.Create())
            {
                return "v1:" + timestamp + ":" + method.ToUpperInvariant() + ":" + path + ":" + Hex(sha.ComputeHash(body));
            }
        }

        public static string Sign(string secret, string timestamp, string method, string path, byte[] body)
        {
            using (var mac = new HMACSHA256(Encoding.UTF8.GetBytes(secret)))
            {
                return Hex(mac.ComputeHash(Encoding.UTF8.GetBytes(Canonical(timestamp, method, path, body))));
            }
        }
    }

    // Trusts the installation's own certificate authority for this connection, and nothing else.
    public sealed class Pin
    {
        readonly X509Certificate2 root;

        public Pin(string pem)
        {
            if (string.IsNullOrEmpty(pem)) return;
            const string begin = "-----BEGIN CERTIFICATE-----", end = "-----END CERTIFICATE-----";
            int a = pem.IndexOf(begin, StringComparison.Ordinal), b = pem.IndexOf(end, StringComparison.Ordinal);
            if (a < 0 || b < a) throw new CollectorException("root_certificate in config.json is not a certificate");
            string body = pem.Substring(a + begin.Length, b - a - begin.Length).Replace("\r", "").Replace("\n", "").Trim();
            root = new X509Certificate2(System.Convert.FromBase64String(body));
        }

        public bool Pinned { get { return root != null; } }

        public string Fingerprint
        {
            get
            {
                if (root == null) return null;
                using (var sha = SHA256.Create()) return Signer.Hex(sha.ComputeHash(root.RawData));
            }
        }

        public bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            // With no pinned certificate, the computer's own trust decides, as for any website.
            if (root == null) return errors == SslPolicyErrors.None;
            if (certificate == null) return false;
            using (var check = new X509Chain())
            {
                check.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                check.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                check.ChainPolicy.ExtraStore.Add(root);
                if (chain != null)
                {
                    foreach (var element in chain.ChainElements) check.ChainPolicy.ExtraStore.Add(element.Certificate);
                }
                var leaf = new X509Certificate2(certificate);
                if (!check.Build(leaf)) return false;
                var top = check.ChainElements[check.ChainElements.Count - 1].Certificate;
                // The chain must end at exactly the pinned certificate. A name mismatch is accepted, because only
                // this installation's authority can have issued the certificate, whatever address was used.
                return top.RawData.Length == root.RawData.Length && Equal(top.RawData, root.RawData);
            }
        }

        static bool Equal(byte[] a, byte[] b)
        {
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }
    }

    public sealed class Result
    {
        public int Status;
        public string Body;
    }

    public static class Http
    {
        public static Result Post(Config config, Pin pin, string path, byte[] body)
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var request = (HttpWebRequest)WebRequest.Create(config.ApiUrl.TrimEnd('/') + path);
            request.Method = "POST";
            request.ContentType = "application/json";
            request.UserAgent = "htm-windows-collector/0.7";
            request.Timeout = 60000;
            request.ReadWriteTimeout = 60000;
            request.ServerCertificateValidationCallback = pin.Validate;
            string timestamp = ((long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds).ToString(CultureInfo.InvariantCulture);
            request.Headers["x-htm-key-id"] = config.CollectorId;
            request.Headers["x-htm-timestamp"] = timestamp;
            request.Headers["x-htm-signature"] = Signer.Sign(config.Secret, timestamp, "POST", path, body);
            request.ContentLength = body.Length;
            try
            {
                using (var stream = request.GetRequestStream()) stream.Write(body, 0, body.Length);
                using (var response = (HttpWebResponse)request.GetResponse()) return Read(response);
            }
            catch (WebException err)
            {
                var response = err.Response as HttpWebResponse;
                if (response != null) using (response) return Read(response);
                if (err.Status == WebExceptionStatus.TrustFailure || err.Status == WebExceptionStatus.SecureChannelFailure || CertificateProblem(err))
                    throw new CollectorException("The platform's certificate is not the one this computer was set up to trust. Download the installer again from the console.");
                throw new CollectorException("Could not reach the platform at " + config.ApiUrl + ": " + err.Message);
            }
        }

        static bool CertificateProblem(Exception err)
        {
            for (var e = err.InnerException; e != null; e = e.InnerException)
            {
                if (e is System.Security.Authentication.AuthenticationException) return true;
            }
            return false;
        }

        static Result Read(HttpWebResponse response)
        {
            using (var reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
            {
                var r = new Result();
                r.Status = (int)response.StatusCode;
                r.Body = reader.ReadToEnd();
                return r;
            }
        }
    }

    public static class Collector
    {
        public const int BatchSize = 500;

        static string StatePath(string dir) { return Path.Combine(dir, "state.json"); }

        static Dictionary<string, object> LoadState(string dir)
        {
            try
            {
                var parsed = Json.Parse(File.ReadAllText(StatePath(dir), Encoding.UTF8)) as Dictionary<string, object>;
                return parsed ?? new Dictionary<string, object>();
            }
            catch (FileNotFoundException) { return new Dictionary<string, object>(); }
            catch (CollectorException) { return new Dictionary<string, object>(); }
        }

        /// <summary>The last record sent from a log, or -1 when nothing has been sent from it yet.</summary>
        public static long LastRecordId(string dir, string channel)
        {
            object v;
            return LoadState(dir).TryGetValue(channel, out v) && v is double ? (long)(double)v : -1;
        }

        /// <summary>Starts a log at a record, only if nothing has been sent from it yet.</summary>
        public static void Start(string dir, string channel, long recordId)
        {
            if (LastRecordId(dir, channel) < 0) SaveState(dir, channel, recordId);
        }

        static void SaveState(string dir, string channel, long recordId)
        {
            var state = LoadState(dir);
            state[channel] = (double)recordId;
            string temp = StatePath(dir) + ".tmp";
            File.WriteAllText(temp, Json.Write(state), new UTF8Encoding(false));
            if (File.Exists(StatePath(dir))) File.Delete(StatePath(dir));
            File.Move(temp, StatePath(dir));
        }

        /// <summary>Sends events from one log. Returns a line for the collector's own log file.</summary>
        public static string Process(string dir, string channel, string[] events)
        {
            return Process(dir, channel, events, -1);
        }

        /// <summary>Sends one page of events. Once all of it is handled, the position moves to the end of the page,
        /// even past events that could not be read, so one unreadable event cannot hold the log back.</summary>
        public static string Process(string dir, string channel, string[] events, long pageEnd)
        {
            var config = Config.Load(Path.Combine(dir, "config.json"));
            var pin = new Pin(config.RootCertificate);
            var records = new List<KeyValuePair<long, Dictionary<string, object>>>();
            int unreadable = 0;
            foreach (string xml in events ?? new string[0])
            {
                try
                {
                    var r = EventConverter.Convert(xml);
                    records.Add(new KeyValuePair<long, Dictionary<string, object>>(long.Parse((string)r["RecordId"], CultureInfo.InvariantCulture), r));
                }
                catch (Exception err)
                {
                    if (err is XmlException || err is CollectorException || err is FormatException || err is OverflowException) unreadable++;
                    else throw;
                }
            }
            records.Sort(delegate (KeyValuePair<long, Dictionary<string, object>> a, KeyValuePair<long, Dictionary<string, object>> b) { return a.Key.CompareTo(b.Key); });
            long stored = 0, duplicate = 0, refused = 0;
            for (int start = 0; start < records.Count; start += BatchSize)
            {
                int count = Math.Min(BatchSize, records.Count - start);
                var batch = new List<object>();
                for (int i = start; i < start + count; i++)
                {
                    var item = new Dictionary<string, object>();
                    item["source"] = "windows";
                    item["payload"] = records[i].Value;
                    batch.Add(item);
                }
                var envelope = new Dictionary<string, object>();
                envelope["batch_id"] = Guid.NewGuid().ToString();
                envelope["run_id"] = null;
                envelope["records"] = batch;
                byte[] body = new UTF8Encoding(false).GetBytes(Json.Write(envelope));
                var result = Http.Post(config, pin, "/api/ingest", body);
                if (result.Status != 200) throw new CollectorException(Explain(result));
                var reply = Json.Parse(result.Body) as Dictionary<string, object>;
                stored += Number(reply, "accepted");
                duplicate += Number(reply, "duplicate");
                refused += Number(reply, "rejected");
                // Only now is the position saved, so a failed batch is sent again next time.
                SaveState(dir, channel, records[start + count - 1].Key);
            }
            if (pageEnd > LastRecordId(dir, channel)) SaveState(dir, channel, pageEnd);
            return string.Format(CultureInfo.InvariantCulture, "{0}: {1} events read, {2} stored, {3} already stored, {4} refused, {5} unreadable",
                channel, records.Count + unreadable, stored, duplicate, refused, unreadable);
        }

        static long Number(Dictionary<string, object> o, string key)
        {
            object v;
            return o != null && o.TryGetValue(key, out v) && v is double ? (long)(double)v : 0;
        }

        public static string Explain(Result result)
        {
            string reason = null;
            try
            {
                var o = Json.Parse(result.Body) as Dictionary<string, object>;
                object v;
                if (o != null && o.TryGetValue("error", out v)) reason = v as string;
            }
            catch (CollectorException) { }
            switch (reason)
            {
                case "timestamp_outside_window": return "This computer's clock is more than a few minutes away from the platform's. Correct the clock.";
                case "bad_signature":
                case "signature_mismatch": return "The secret in config.json was refused. Download the installer again from the console.";
                case "collector_not_registered": return "This group of computers was removed or switched off in the console.";
                case "too_many_requests": return "The platform asked this computer to slow down. It will try again next time.";
                default: return "The platform refused the events (" + result.Status + (reason == null ? "" : ", " + reason) + ").";
            }
        }
    }
}
