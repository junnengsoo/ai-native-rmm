param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^rmm-[0-9a-f]{32}$')]
    [string]$PipeName
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

$support = @'
using System;
using System.Globalization;
using System.IO;
using System.Management.Automation.Host;
using System.Text;

public sealed class RmmInvocationHost : PSHost
{
    private readonly Guid instanceId = Guid.NewGuid();
    public int? ExitCode { get; set; }
    public override Guid InstanceId { get { return instanceId; } }
    public override string Name { get { return "RmmExecutionWorker"; } }
    public override Version Version { get { return new Version(1, 0); } }
    public override PSHostUserInterface UI { get { return null; } }
    public override CultureInfo CurrentCulture { get { return CultureInfo.InvariantCulture; } }
    public override CultureInfo CurrentUICulture { get { return CultureInfo.InvariantCulture; } }
    public override void SetShouldExit(int exitCode) { ExitCode = exitCode; }
    public override void EnterNestedPrompt() { throw new NotSupportedException(); }
    public override void ExitNestedPrompt() { throw new NotSupportedException(); }
    public override void NotifyBeginApplication() { }
    public override void NotifyEndApplication() { }
}

public static class RmmProtocol
{
    private const int ChunkLimit = 8192;

    public static void WriteLine(StreamWriter writer, string json)
    {
        lock (writer) { writer.WriteLine(json); }
    }

    public static void WriteOutput(StreamWriter writer, string stream, string value)
    {
        if (String.IsNullOrEmpty(value)) return;
        lock (writer)
        {
            var chunk = new StringBuilder();
            int chunkBytes = 0;
            for (int index = 0; index < value.Length;)
            {
                int charCount = Char.IsHighSurrogate(value[index]) && index + 1 < value.Length ? 2 : 1;
                int byteCount = Encoding.UTF8.GetByteCount(value.ToCharArray(), index, charCount);
                if (chunk.Length > 0 && chunkBytes + byteCount > ChunkLimit)
                {
                    WriteOutputLine(writer, stream, chunk.ToString());
                    chunk.Clear();
                    chunkBytes = 0;
                }
                chunk.Append(value, index, charCount);
                chunkBytes += byteCount;
                index += charCount;
            }
            if (chunk.Length > 0) WriteOutputLine(writer, stream, chunk.ToString());
        }
    }

    private static void WriteOutputLine(StreamWriter writer, string stream, string text)
    {
        writer.Write("{\"kind\":\"output\",\"stream\":\"");
        writer.Write(stream);
        writer.Write("\",\"text\":\"");
        WriteEscaped(writer, text);
        writer.WriteLine("\"}");
    }

    private static void WriteEscaped(TextWriter writer, string value)
    {
        foreach (char character in value)
        {
            switch (character)
            {
                case '\"': writer.Write("\\\""); break;
                case '\\': writer.Write("\\\\"); break;
                case '\b': writer.Write("\\b"); break;
                case '\f': writer.Write("\\f"); break;
                case '\n': writer.Write("\\n"); break;
                case '\r': writer.Write("\\r"); break;
                case '\t': writer.Write("\\t"); break;
                default:
                    if (character < 0x20) writer.Write("\\u" + ((int)character).ToString("x4"));
                    else writer.Write(character);
                    break;
            }
        }
    }
}

public sealed class RmmConsoleWriter : TextWriter
{
    private readonly StreamWriter writer;
    private readonly string stream;
    public RmmConsoleWriter(StreamWriter writer, string stream) { this.writer = writer; this.stream = stream; }
    public override Encoding Encoding { get { return Encoding.UTF8; } }
    public override void Write(char value) { RmmProtocol.WriteOutput(writer, stream, value.ToString()); }
    public override void Write(string value) { RmmProtocol.WriteOutput(writer, stream, value); }
}
'@

$pipe = $null
$reader = $null
$writer = $null
$runspace = $null
$stage = 'pipe_connect'

try {
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
        '.', $PipeName,
        [System.IO.Pipes.PipeDirection]::InOut,
        [System.IO.Pipes.PipeOptions]::Asynchronous
    )
    $pipe.Connect(15000)
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $reader = New-Object System.IO.StreamReader($pipe, $utf8, $false, 4096, $true)
    $writer = New-Object System.IO.StreamWriter($pipe, $utf8, 4096, $true)
    $writer.AutoFlush = $true

    $stage = 'support_compile'
    Add-Type -TypeDefinition $support -Language CSharp

    $stage = 'runspace_open'
    $hostAdapter = New-Object RmmInvocationHost
    $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($hostAdapter)
    $runspace.Open()

    $ready = [ordered]@{
        kind = 'ready'
        version = $PSVersionTable.PSVersion.ToString()
        edition = if ($PSVersionTable.PSObject.Properties.Name -contains 'PSEdition') { $PSVersionTable.PSEdition } else { 'Desktop' }
        is64Bit = [Environment]::Is64BitProcess
        languageMode = $runspace.SessionStateProxy.LanguageMode.ToString()
    } | ConvertTo-Json -Compress
    [RmmProtocol]::WriteLine($writer, $ready)
    $stage = 'running'

    [Console]::SetOut((New-Object RmmConsoleWriter($writer, 'stdout')))
    [Console]::SetError((New-Object RmmConsoleWriter($writer, 'stderr')))

    while (($line = $reader.ReadLine()) -ne $null) {
        $request = $line | ConvertFrom-Json
        $script = [string]$request.script
        $hostAdapter.ExitCode = $null
        $runspace.SessionStateProxy.SetVariable('LASTEXITCODE', $null)
        $powershell = [PowerShell]::Create()
        $powershell.Runspace = $runspace
        [void]$powershell.AddScript($script, $false)
        $output = New-Object 'System.Management.Automation.PSDataCollection[System.Management.Automation.PSObject]'
        $pipelineInput = New-Object 'System.Management.Automation.PSDataCollection[System.Management.Automation.PSObject]'
        $pipelineInput.Complete()
        $outputIndex = 0
        $errorIndex = 0
        $warningIndex = 0
        $informationIndex = 0
        $hadErrors = $false
        $terminated = $false
        $watch = [Diagnostics.Stopwatch]::StartNew()

        try {
            $beginInvoke = [PowerShell].GetMethods() |
                Where-Object {
                    $_.Name -eq 'BeginInvoke' -and
                    $_.IsGenericMethodDefinition -and
                    $_.GetParameters().Count -eq 2
                } |
                Select-Object -First 1
            if ($null -eq $beginInvoke) { throw 'compatible_begin_invoke_missing' }
            $genericBeginInvoke = $beginInvoke.MakeGenericMethod([psobject], [psobject])
            $pending = $genericBeginInvoke.Invoke($powershell, [object[]]@($pipelineInput, $output))
            while (-not $pending.IsCompleted) {
                while ($outputIndex -lt $output.Count) {
                    [RmmProtocol]::WriteOutput($writer, 'stdout', ([string]$output[$outputIndex] + "`n"))
                    $outputIndex++
                }
                while ($errorIndex -lt $powershell.Streams.Error.Count) {
                    $hadErrors = $true
                    [RmmProtocol]::WriteOutput($writer, 'stderr', ([string]$powershell.Streams.Error[$errorIndex] + "`n"))
                    $errorIndex++
                }
                while ($warningIndex -lt $powershell.Streams.Warning.Count) {
                    [RmmProtocol]::WriteOutput($writer, 'stderr', ($powershell.Streams.Warning[$warningIndex].Message + "`n"))
                    $warningIndex++
                }
                while ($informationIndex -lt $powershell.Streams.Information.Count) {
                    [RmmProtocol]::WriteOutput($writer, 'stdout', ([string]$powershell.Streams.Information[$informationIndex].MessageData + "`n"))
                    $informationIndex++
                }
                Start-Sleep -Milliseconds 10
            }
            try { [void]$powershell.EndInvoke($pending) }
            catch { $terminated = $true }
        } catch {
            $terminated = $true
            [RmmProtocol]::WriteOutput($writer, 'stderr', ([string]$_ + "`n"))
        } finally {
            while ($outputIndex -lt $output.Count) {
                [RmmProtocol]::WriteOutput($writer, 'stdout', ([string]$output[$outputIndex] + "`n"))
                $outputIndex++
            }
            while ($errorIndex -lt $powershell.Streams.Error.Count) {
                $hadErrors = $true
                [RmmProtocol]::WriteOutput($writer, 'stderr', ([string]$powershell.Streams.Error[$errorIndex] + "`n"))
                $errorIndex++
            }
            while ($warningIndex -lt $powershell.Streams.Warning.Count) {
                [RmmProtocol]::WriteOutput($writer, 'stderr', ($powershell.Streams.Warning[$warningIndex].Message + "`n"))
                $warningIndex++
            }
            while ($informationIndex -lt $powershell.Streams.Information.Count) {
                [RmmProtocol]::WriteOutput($writer, 'stdout', ([string]$powershell.Streams.Information[$informationIndex].MessageData + "`n"))
                $informationIndex++
            }
            $watch.Stop()
        }

        $nativeCode = $runspace.SessionStateProxy.GetVariable('LASTEXITCODE')
        $explicitExit = $null -ne $hostAdapter.ExitCode
        $result = [ordered]@{
            State = 'completed'
            InvocationOutcome = if ($explicitExit) { 'explicit_exit' } elseif ($terminated) { 'terminating_error' } else { 'completed_normally' }
            ExitCode = if ($explicitExit) { $hostAdapter.ExitCode } elseif ($terminated) { 1 } else { 0 }
            ExitCodeSource = if ($explicitExit) { 'explicit_script_exit' } else { 'normalized_invocation' }
            HadErrors = $hadErrors -or $terminated
            DurationMs = $watch.Elapsed.TotalMilliseconds
            CaptureTruncated = $false
            LastNativeExitCode = if ($nativeCode -is [int]) { $nativeCode } else { $null }
        } | ConvertTo-Json -Compress
        [RmmProtocol]::WriteLine($writer, $result)
        $powershell.Dispose()
        $pipelineInput.Dispose()
        $output.Dispose()
        if ($explicitExit) { break }
    }
} catch {
    try {
        $failure = 'startup_failed:' + $stage
        if ($null -ne $writer) { $writer.WriteLine($failure) }
        [Console]::Error.WriteLine($failure)
    } catch { }
    exit 1
} finally {
    if ($null -ne $runspace) { $runspace.Dispose() }
    if ($null -ne $reader) { $reader.Dispose() }
    if ($null -ne $writer) { $writer.Dispose() }
    if ($null -ne $pipe) { $pipe.Dispose() }
}
