using namespace System.Management.Automation
using namespace System.Management.Automation.Language

Register-ArgumentCompleter -CommandName docseal -ScriptBlock {
    param($commandName, $wordToComplete, $cursorPosition)

    $inputLine = $null
    $cursor = $null
    [Parser]::ParseInput($args[2], [ref]$inputLine, [ref]$null) | Out-Null

    $commands = @("encrypt", "decrypt")
    $common = @("--out", "--force", "--allow-large", "--password", "--password-file", "--keep-original", "--delete-original", "--i-understand", "--debug", "-h", "--help")
    $encryptOnly = @("--algo", "--kdf")

    $tokens = $args[2].Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
    if ($tokens.Count -le 1) {
        $commands + @("-h", "--help") | Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object { [CompletionResult]::new($_, $_, "ParameterValue", $_) }
        return
    }

    $cmd = $tokens[1]
    if ($cmd -eq "encrypt") {
        ($common + $encryptOnly) | Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object { [CompletionResult]::new($_, $_, "ParameterValue", $_) }
        return
    }
    if ($cmd -eq "decrypt") {
        $common | Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object { [CompletionResult]::new($_, $_, "ParameterValue", $_) }
        return
    }

    ($commands + $common) | Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object { [CompletionResult]::new($_, $_, "ParameterValue", $_) }
}
