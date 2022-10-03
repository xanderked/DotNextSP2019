using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Etlx;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SimpleKernelConsumer {
	class ProcessInfo {
		public long Id { get; set; }
		public string Name { get; set; }
	}

	class Program {
		static void Main(string[] args) {
			var processes = Process.GetProcesses().Select(p => new ProcessInfo {
				Name = p.ProcessName,
				Id = p.Id
			}).ToDictionary(p => p.Id);

			Console.ForegroundColor = ConsoleColor.White;
			Console.WriteLine("Event Time,Event Type,Event Param,Orig Process,Addl Event Params");

			using (var session = new TraceEventSession(Environment.OSVersion.Version.Build >= 9200 ? "MyKernelSession" : KernelTraceEventParser.KernelSessionName)) {
				session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.ImageLoad | KernelTraceEventParser.Keywords.NetworkTCPIP | KernelTraceEventParser.Keywords.FileIOInit);
				var parser = session.Source.Kernel;

				parser.ProcessStart += e => {
					Console.ForegroundColor = ConsoleColor.Green;
					Console.WriteLine($"{e.TimeStamp.ToString("s")}.{e.TimeStamp.Millisecond:D3},New Process,Process {e.ProcessID} ({e.ProcessName}),process {e.ParentID},{e.CommandLine}");
					processes.Add(e.ProcessID, new ProcessInfo { Id = e.ProcessID, Name = e.ProcessName });
				};
				parser.ProcessStop += e => {
					Console.ForegroundColor = ConsoleColor.Red;
					Console.WriteLine($"{e.TimeStamp.ToString("s")}.{e.TimeStamp.Millisecond:D3},End Process,Exit Status {e.ExitStatus},process {e.ProcessID} ({TryGetProcessName(e)})");
				};

				parser.ImageLoad += e => {
					Console.ForegroundColor = ConsoleColor.Yellow;
					var name = TryGetProcessName(e);
					Console.WriteLine($"{e.TimeStamp.ToString("s")}.{e.TimeStamp.Millisecond:D3},Image Loaded,{e.FileName},process {e.ProcessID} ({name}),Size=0x{e.ImageSize:X}");
				};

				parser.ImageUnload += e => {
					Console.ForegroundColor = ConsoleColor.DarkYellow;
					var name = TryGetProcessName(e);
					Console.WriteLine($"{e.TimeStamp.ToString("s")}.{e.TimeStamp.Millisecond:D3},Image Unloaded,{e.FileName},process {e.ProcessID} ({name})");
				};

				parser.TcpIpSend += e => {
					Console.ForegroundColor = ConsoleColor.Blue;
					var name = TryGetProcessName(e);
					Console.WriteLine($"{e.TimeStamp.ToString("s")}.{e.TimeStamp.Millisecond:D3},TCPv4 Send to,{e.daddr}:{e.dport},process {e.ProcessID} ({name})");
				};

                parser.TcpIpSendIPV6 += e => {
                    Console.ForegroundColor = ConsoleColor.Blue;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp}.{e.TimeStamp.Millisecond:D3},TCPv6 Send to,{e.daddr}:{e.dport},process {e.ProcessID} ({name})");
                };

                parser.TcpIpRecv += e => {
					Console.ForegroundColor = ConsoleColor.DarkBlue;
					var name = TryGetProcessName(e);
					Console.WriteLine($"{e.TimeStamp.ToString("s")}.{e.TimeStamp.Millisecond:D3},TCPv4 Receive from,{e.daddr}:{e.dport},process {e.ProcessID} ({name})");
				};

                parser.TcpIpRecvIPV6 += e => {
                    Console.ForegroundColor = ConsoleColor.DarkBlue;
                    var name = TryGetProcessName(e);
                    Console.WriteLine($"{e.TimeStamp.ToString("s")}.{e.TimeStamp.Millisecond:D3},TCPv6 Receive from,{e.daddr}:{e.dport},process {e.ProcessID} ({name})");
                };

                parser.FileIOOperationEnd += e => {
					Console.ForegroundColor = ConsoleColor.DarkMagenta;
					var name = TryGetProcessName(e);
					Console.WriteLine($"{e.TimeStamp.ToString("s")}.{e.TimeStamp.Millisecond:D3},File IO Operation End,{e.EventName}),process {e.ProcessID} ({name})");
				};

				parser.RegistryQuery += e => {
					Console.ForegroundColor = ConsoleColor.Cyan;
					var name = TryGetProcessName(e);
					Console.WriteLine($"{e.TimeStamp.ToString("s")}.{e.TimeStamp.Millisecond:D3},Registry Query for Key,{e.KeyName}),process {e.ProcessID} ({name})");
				};

				Task.Run(() => session.Source.Process());
				Thread.Sleep(TimeSpan.FromSeconds(20));

			}

			string TryGetProcessName(TraceEvent evt) {
				if (!string.IsNullOrEmpty(evt.ProcessName))
					return evt.ProcessName;
				return processes.TryGetValue(evt.ProcessID, out var info) ? info.Name : string.Empty;
			}
		}
	}
}
