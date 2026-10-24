// Tests for the Windows collector's core. Written for C# 5, like the collector.
//   dotnet run -- unit                         checks conversion, signing, configuration and JSON
//   dotnet run -- send <folder> <log> <files>  sends sample events with the config.json in <folder>, like the collector does

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using HealthcareThreatMonitor;

static class Tests
{
    static int failures;

    static void Check(string name, bool ok, string detail)
    {
        Console.WriteLine((ok ? "PASS " : "FAIL ") + name + (ok || detail == null ? "" : ": " + detail));
        if (!ok) failures++;
    }

    static string Sample(string name)
    {
        return File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "samples", name + ".xml"));
    }

    static Dictionary<string, object> Data(Dictionary<string, object> record)
    {
        return (Dictionary<string, object>)record["Data"];
    }

    static void Unit()
    {
        // The signature must match the platform's. These values come from web/tests/signing.test.ts.
        string sig = Signer.Sign("4f77f91d662217a01618981516897e90e54d127ebb31ea34545b9e72e8f452f5", "1760000000", "POST", "/api/ingest",
            Encoding.UTF8.GetBytes("{\"a\":1}"));
        Check("signature matches the platform's test vector", sig == "310a45b5e2aaff8f823736eb10a0a0f7f22e5c2f65aaa9740a1757273a424545", sig);

        var logon = EventConverter.Convert(Sample("4624"));
        Check("logon: record number, computer, ID and log", (string)logon["RecordId"] == "184467" && (string)logon["Computer"] == "WSED001.hospital.local"
            && (long)logon["EventID"] == 4624 && (string)logon["Channel"] == "Security", Json.Write(logon));
        Check("logon: time kept to the millisecond in UTC", (string)logon["TimeCreated"] == "2026-10-22T10:15:04.123Z", (string)logon["TimeCreated"]);
        Check("logon: the fields the platform reads are kept", (string)Data(logon)["TargetUserName"] == "abaker" && (string)Data(logon)["LogonType"] == "2",
            Json.Write(Data(logon)));
        Check("logon: everything else stays on the computer", !Data(logon).ContainsKey("TargetUserSid") && !Data(logon).ContainsKey("LogonGuid")
            && !Data(logon).ContainsKey("ElevatedToken"), string.Join(",", Data(logon).Keys));

        var failed = EventConverter.Convert(Sample("4625"));
        Check("failed logon: address and reason", (string)Data(failed)["IpAddress"] == "10.40.0.66" && (string)Data(failed)["SubStatus"] == "0xc000006a",
            Json.Write(Data(failed)));

        var process = EventConverter.Convert(Sample("4688"));
        Check("process: command line exactly as typed", (string)Data(process)["CommandLine"] == "\"C:\\Windows\\system32\\vssadmin.exe\" delete shadows /all /quiet",
            Json.Write(Data(process)));
        Check("process: program and parent", (string)Data(process)["NewProcessName"] == "C:\\Windows\\System32\\vssadmin.exe"
            && (string)Data(process)["ParentProcessName"] == "C:\\Windows\\System32\\cmd.exe", Json.Write(Data(process)));

        var cleared = EventConverter.Convert(Sample("1102"));
        Check("log cleared: who cleared it, from UserData", (long)cleared["EventID"] == 1102 && (string)Data(cleared)["SubjectUserName"] == "tusman"
            && !Data(cleared).ContainsKey("SubjectUserSid"), Json.Write(cleared));

        var service = EventConverter.Convert(Sample("7036"));
        Check("service: ID read despite its Qualifiers, name and state kept", (long)service["EventID"] == 7036 && (string)service["Channel"] == "System"
            && (string)Data(service)["param1"] == "Volume Shadow Copy" && (string)Data(service)["param2"] == "stopped", Json.Write(service));

        bool refused = false;
        try
        {
            EventConverter.Convert("<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>&e;</EventID></System></Event>");
        }
        catch (Exception) { refused = true; }
        Check("an event with an external entity is refused, not read", refused, null);

        string longLine = new string('x', 5000);
        var big = EventConverter.Convert(Sample("4688").Replace("delete shadows /all /quiet", longLine));
        Check("very long values are cut to 2000 characters", ((string)Data(big)["CommandLine"]).Length == 2000, null);

        var round = Json.Parse(Json.Write(new Dictionary<string, object> { { "a", "line\n\"quoted\" \\ \u0001" }, { "n", 5L }, { "z", null }, { "l", new List<object> { true, 1.5 } } }))
            as Dictionary<string, object>;
        Check("JSON written and read back unchanged", round != null && (string)round["a"] == "line\n\"quoted\" \\ \u0001" && (double)round["n"] == 5
            && round["z"] == null && ((List<object>)round["l"]).Count == 2, null);

        string dir = Path.Combine(Path.GetTempPath(), "htm-config-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "config.json");
        File.WriteAllText(path, "{\"api_url\":\"http://10.0.0.5\",\"collector_id\":\"win_x\",\"secret\":\"s\"}");
        refused = false;
        try { Config.Load(path); } catch (CollectorException) { refused = true; }
        Check("unencrypted http to another computer is refused", refused, null);
        File.WriteAllText(path, "{\"api_url\":\"http://127.0.0.1:8080\",\"collector_id\":\"win_x\",\"secret\":\"s\",\"interval_minutes\":5}");
        Check("http to this same computer is allowed for testing", Config.Load(path).IntervalMinutes == 5, null);
        Check("a new log starts from nothing", Collector.LastRecordId(dir, "Security") == -1, null);
        Directory.Delete(dir, true);

        var tooOld = new Result();
        tooOld.Status = 401;
        tooOld.Body = "{\"ok\":false,\"error\":\"timestamp_outside_window\"}";
        Check("a wrong clock is explained in plain words", Collector.Explain(tooOld).Contains("clock"), Collector.Explain(tooOld));
    }

    static int Main(string[] args)
    {
        if (args.Length >= 1 && args[0] == "unit")
        {
            Unit();
            Console.WriteLine(failures == 0 ? "RESULT: PASS" : "RESULT: FAIL, " + failures + " failed");
            return failures == 0 ? 0 : 1;
        }
        if (args.Length >= 4 && args[0] == "page")
        {
            // Like the collector script: one page, ending at the given record, with whatever events it holds.
            var pageXml = args.Skip(4).Select(f => File.ReadAllText(f)).ToArray();
            try
            {
                Console.WriteLine(Collector.Process(args[1], args[2], pageXml, long.Parse(args[3])));
                Console.WriteLine("last record now " + Collector.LastRecordId(args[1], args[2]));
                return 0;
            }
            catch (CollectorException err)
            {
                Console.WriteLine("ERROR " + err.Message);
                return 2;
            }
        }
        if (args.Length >= 4 && args[0] == "send")
        {
            var xml = args.Skip(3).Select(f => File.ReadAllText(f)).ToArray();
            try
            {
                Console.WriteLine(Collector.Process(args[1], args[2], xml));
                Console.WriteLine("last record now " + Collector.LastRecordId(args[1], args[2]));
                return 0;
            }
            catch (CollectorException err)
            {
                Console.WriteLine("ERROR " + err.Message);
                return 2;
            }
        }
        Console.WriteLine("Usage: dotnet run -- unit | send <folder> <log> <event files>");
        return 1;
    }
}
