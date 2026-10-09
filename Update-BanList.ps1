<#
    Update-BanList.ps1

    Собирает IP-адреса, подбирающие пароли SMTP AUTH на серверах Eserv
    ("530 Auth wrong"), и публикует ban.txt для FortiGate External Connector.

    Как работает:
      - логи читаются ИНКРЕМЕНТАЛЬНО: скрипт запоминает, до какого байта прочитал
        каждый файл, и при следующем запуске читает только новые строки.
        Первый запуск прочитает файлы целиком (может занять несколько минут),
        дальше каждый запуск обрабатывает только то, что добавилось;
      - IP банится, если набрал Threshold неудачных попыток в пределах WindowHours
        часов (время берётся из строк лога);
      - бан держится BanDays дней после последней замеченной попытки, затем снимается;
      - адреса и диапазоны из Whitelist не банятся никогда;
      - ручной список ban_manual.txt всегда попадает в ban.txt
        (при первом запуске он создаётся из текущего ban.txt);
      - если с IP, с которого подбирали пароль, был УСПЕШНЫЙ вход,
        в alerts.log пишется предупреждение (возможен взлом учётки).

    Настройки лежат в отдельном файле config.psd1 (шаблон: config.example.psd1).
    По умолчанию скрипт ищет config.psd1 рядом с собой; другой путь можно
    передать параметром -ConfigPath.

    Запуск: Планировщик заданий, каждые 10 минут.
    Совместим с Windows PowerShell 5.1.

    .PARAMETER ConfigPath
    Путь к файлу настроек (.psd1). По умолчанию config.psd1 в папке скрипта.
#>

param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config.psd1')
)

# ======================= НАСТРОЙКИ =======================

if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Файл настроек не найден: '$ConfigPath'. Скопируйте config.example.psd1 в config.psd1 и отредактируйте."
}
$cfg = Import-PowerShellDataFile -Path $ConfigPath

foreach ($key in 'LogPaths', 'WorkDir', 'BanFile') {
    if (-not $cfg.ContainsKey($key) -or -not $cfg[$key]) {
        throw "В файле настроек '$ConfigPath' не задан обязательный параметр '$key'."
    }
}

# Необязательные параметры: если в config.psd1 не заданы, берутся значения по умолчанию
function Get-Setting([string]$Name, $Default) {
    if ($cfg.ContainsKey($Name) -and $null -ne $cfg[$Name]) { return $cfg[$Name] }
    return $Default
}

$LogPaths       = @($cfg.LogPaths)    # маска *log.txt подхватывает помесячные файлы логов
$WorkDir        = $cfg.WorkDir
$BanFile        = $cfg.BanFile       # файл, который отдаёт веб-сервер для FortiGate

$MaxFileAgeDays = [int](Get-Setting 'MaxFileAgeDays' 35)   # обрабатывать только файлы, изменённые за последние N дней
$WindowHours    = [int](Get-Setting 'WindowHours'    24)   # окно подсчёта неудачных попыток
$Threshold      = [int](Get-Setting 'Threshold'      5)    # неудачных попыток за окно, чтобы забанить
$BanDays        = [int](Get-Setting 'BanDays'        30)   # сколько дней держать бан после последней попытки

$FailPattern    = [string](Get-Setting 'FailPattern'   '530 Auth wrong')  # неудачная авторизация в логе Eserv
$SuccessPrefix  = [string](Get-Setting 'SuccessPrefix' '235')             # код ответа на успешную авторизацию
$ChunkSize      = [int](Get-Setting 'ChunkSizeMB' 4) * 1MB                # размер блока чтения
$LogEncoding    = [Text.Encoding]::GetEncoding([int](Get-Setting 'LogEncodingCodePage' 1251))

$Whitelist      = @(Get-Setting 'Whitelist' @())   # никогда не банить: подсеть, диапазон или один IP

$ManualFile     = Join-Path $WorkDir 'ban_manual.txt'   # ручной список: IP, подсеть или диапазон, по одному в строке
$BannedFile     = Join-Path $WorkDir 'banned.csv'       # автоматические баны со сроками
$PendingFile    = Join-Path $WorkDir 'pending.csv'      # IP, набирающие попытки (ещё не забанены)
$OffsetFile     = Join-Path $WorkDir 'offsets.csv'      # до какого байта прочитан каждый лог
$ScriptLog      = Join-Path $WorkDir 'update.log'
$AlertLog       = Join-Path $WorkDir 'alerts.log'

# ======================= ФУНКЦИИ =======================

function Write-Log([string]$Message, [string]$File = $ScriptLog) {
    $line = '{0:yyyy-MM-dd HH:mm:ss}  {1}' -f (Get-Date), $Message
    Add-Content -Path $File -Value $line -Encoding UTF8
}

function Test-IPv4([string]$Ip) {
    if ($Ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    $addr = $null
    return [System.Net.IPAddress]::TryParse($Ip, [ref]$addr)
}

function ConvertTo-IpNumber([string]$Ip) {
    $bytes = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [int64][BitConverter]::ToUInt32($bytes, 0)
}

function ConvertTo-IpRange([string]$Entry) {
    $e = $Entry.Trim()
    if ($e -match '^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$') {
        return [pscustomobject]@{ Start = ConvertTo-IpNumber $Matches[1]; End = ConvertTo-IpNumber $Matches[2] }
    }
    if ($e -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        $ipNum = ConvertTo-IpNumber $Matches[1]
        $size  = [int64][math]::Pow(2, 32 - [int]$Matches[2])
        $start = $ipNum - ($ipNum % $size)
        return [pscustomobject]@{ Start = $start; End = $start + $size - 1 }
    }
    if (Test-IPv4 $e) {
        $n = ConvertTo-IpNumber $e
        return [pscustomobject]@{ Start = $n; End = $n }
    }
    throw "Некорректная запись в белом списке: '$Entry'"
}

$WhitelistRanges = @($Whitelist | ForEach-Object { ConvertTo-IpRange $_ })
$WhitelistCache  = @{}

function Test-Whitelisted([string]$Ip) {
    if ($WhitelistCache.ContainsKey($Ip)) { return $WhitelistCache[$Ip] }
    $n = ConvertTo-IpNumber $Ip
    $result = $false
    foreach ($r in $WhitelistRanges) {
        if ($n -ge $r.Start -and $n -le $r.End) { $result = $true; break }
    }
    $WhitelistCache[$Ip] = $result
    return $result
}

function ConvertTo-LogTime([string]$Text, [datetime]$Default) {
    $t = [datetime]::MinValue
    if ([datetime]::TryParseExact($Text.Trim(), 'yyyy-MM-dd HH:mm:ss',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$t)) { return $t }
    return $Default
}

# ======================= ПОДГОТОВКА =======================

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$startTime = Get-Date
$now = $startTime

# Ротация журнала скрипта
if ((Test-Path $ScriptLog) -and (Get-Item $ScriptLog).Length -gt 5MB) {
    Move-Item $ScriptLog "$ScriptLog.old" -Force
}

# Первый запуск: сохранить текущий ban.txt как ручной список и как резервную копию
if (-not (Test-Path $ManualFile) -and (Test-Path $BanFile)) {
    Copy-Item $BanFile $ManualFile
    Copy-Item $BanFile (Join-Path $WorkDir 'ban_original_backup.txt')
    Write-Log "Первый запуск: текущий ban.txt сохранён как ban_manual.txt и ban_original_backup.txt"
}

# Загрузка состояния
$banned = @{}
if (Test-Path $BannedFile) {
    foreach ($r in Import-Csv $BannedFile) {
        $banned[$r.IP] = [pscustomobject]@{
            IP = $r.IP; FirstSeen = [datetime]$r.FirstSeen; LastSeen = [datetime]$r.LastSeen; Attempts = [int64]$r.Attempts
        }
    }
}
$pending = @{}
if (Test-Path $PendingFile) {
    foreach ($r in Import-Csv $PendingFile) {
        $pending[$r.IP] = [pscustomobject]@{
            IP = $r.IP; WindowStart = [datetime]$r.WindowStart; LastFail = [datetime]$r.LastFail; Count = [int]$r.Count
        }
    }
}
$offsets = @{}
if (Test-Path $OffsetFile) {
    foreach ($r in Import-Csv $OffsetFile) { $offsets[$r.Path] = [int64]$r.Offset }
}

# ======================= ЧТЕНИЕ ЛОГОВ =======================

$since      = $now.AddDays(-$MaxFileAgeDays)
$newOffsets = @{}
$successes  = New-Object System.Collections.Generic.List[object]
$failCount  = 0
$newBans    = 0
$bytesRead  = [int64]0
$filesCount = 0
$successTag = ';' + $SuccessPrefix
$buf        = New-Object byte[] $ChunkSize

foreach ($p in $LogPaths) {
    try {
        $files = @(Get-ChildItem -Path $p -File -ErrorAction Stop | Where-Object { $_.LastWriteTime -ge $since })
    } catch {
        Write-Log "ОШИБКА: не удалось получить список файлов '$p': $($_.Exception.Message)"
        continue
    }

    foreach ($f in $files) {
        $path = $f.FullName
        $len  = [int64]$f.Length
        $off  = [int64]0
        if ($offsets.ContainsKey($path)) { $off = $offsets[$path] }
        if ($off -gt $len) { $off = 0 }    # файл пересоздан или усечён - читать заново
        $filesCount++

        if ($off -eq $len) { $newOffsets[$path] = $off; continue }

        $fs = $null
        try {
            # FileShare ReadWrite: Eserv держит текущий лог открытым на запись
            $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
            [void]$fs.Seek($off, 'Begin')
            $pos   = $off
            $carry = ''

            while ($pos -lt $len) {
                $toRead = [int][math]::Min([int64]$ChunkSize, $len - $pos)
                $n = $fs.Read($buf, 0, $toRead)
                if ($n -le 0) { break }
                $pos += $n

                $text = $carry + $LogEncoding.GetString($buf, 0, $n)
                $nl = $text.LastIndexOf("`n")
                if ($nl -lt 0) { $carry = $text; continue }
                $carry = $text.Substring($nl + 1)

                foreach ($line in $text.Substring(0, $nl).Split("`n")) {
                    $isFail = $line.Contains($FailPattern)
                    if (-not $isFail -and -not $line.Contains($successTag)) { continue }

                    # формат: дата время;IP;учётка;сообщение
                    $parts = $line.Split(';', 4)
                    if ($parts.Count -lt 4) { continue }
                    $ip = $parts[1].Trim()
                    if (-not (Test-IPv4 $ip)) { continue }
                    if (Test-Whitelisted $ip) { continue }
                    $t = ConvertTo-LogTime $parts[0] $now

                    if ($isFail) {
                        $failCount++
                        if ($banned.ContainsKey($ip)) {
                            if ($t -gt $banned[$ip].LastSeen) { $banned[$ip].LastSeen = $t }
                            $banned[$ip].Attempts++
                            continue
                        }
                        $pe = $pending[$ip]
                        if ($null -eq $pe -or ($t - $pe.WindowStart).TotalHours -gt $WindowHours) {
                            $pe = [pscustomobject]@{ IP = $ip; WindowStart = $t; LastFail = $t; Count = 0 }
                            $pending[$ip] = $pe
                        }
                        $pe.Count++
                        if ($t -gt $pe.LastFail) { $pe.LastFail = $t }
                        if ($pe.Count -ge $Threshold) {
                            $banned[$ip] = [pscustomobject]@{
                                IP = $ip; FirstSeen = $pe.WindowStart; LastSeen = $pe.LastFail; Attempts = [int64]$pe.Count
                            }
                            $pending.Remove($ip)
                            $newBans++
                        }
                    }
                    elseif ($parts[3].TrimStart().StartsWith($SuccessPrefix)) {
                        $successes.Add([pscustomobject]@{
                            Time = $t; IP = $ip; User = $parts[2].Trim(); File = $path
                        })
                    }
                }
            }

            # cp1251 - один байт на символ, поэтому длина остатка в символах равна длине в байтах
            $newOffsets[$path] = $pos - $carry.Length
            $bytesRead += ($pos - $off)
        } catch {
            Write-Log "ОШИБКА: не удалось прочитать '$path': $($_.Exception.Message)"
            if ($offsets.ContainsKey($path)) { $newOffsets[$path] = $offsets[$path] }
        } finally {
            if ($fs) { $fs.Close() }
        }
    }
}

# ======================= ПРОВЕРКА НА ВЗЛОМ =======================
# Успешный вход с IP, с которого подбирали пароль (уже забанен или набирает попытки)

$alerts = 0
foreach ($s in $successes) {
    $attempts = $null
    if ($banned.ContainsKey($s.IP))      { $attempts = $banned[$s.IP].Attempts }
    elseif ($pending.ContainsKey($s.IP)) { $attempts = $pending[$s.IP].Count }
    if ($null -ne $attempts) {
        Write-Log ("ВНИМАНИЕ: {0:yyyy-MM-dd HH:mm:ss} успешный вход учётки '{1}' с IP {2}, с которого были неудачные попытки ({3}). Файл: {4}. Проверьте учётку и смените пароль." -f `
            $s.Time, $s.User, $s.IP, $attempts, $s.File) $AlertLog
        $alerts++
    }
}

# ======================= ОЧИСТКА И СОХРАНЕНИЕ =======================

# Снятие просроченных банов
$expired = @($banned.Values | Where-Object { $_.LastSeen -lt $now.AddDays(-$BanDays) })
foreach ($e in $expired) { $banned.Remove($e.IP) }

# Удаление устаревших "кандидатов"
$stale = @($pending.Values | Where-Object { $_.LastFail -lt $now.AddHours(-$WindowHours) })
foreach ($e in $stale) { $pending.Remove($e.IP) }

$banned.Values | Sort-Object IP |
    Select-Object IP,
        @{ n = 'FirstSeen'; e = { $_.FirstSeen.ToString('s') } },
        @{ n = 'LastSeen';  e = { $_.LastSeen.ToString('s') } },
        Attempts |
    Export-Csv -Path $BannedFile -NoTypeInformation -Encoding UTF8

$pending.Values | Sort-Object IP |
    Select-Object IP,
        @{ n = 'WindowStart'; e = { $_.WindowStart.ToString('s') } },
        @{ n = 'LastFail';    e = { $_.LastFail.ToString('s') } },
        Count |
    Export-Csv -Path $PendingFile -NoTypeInformation -Encoding UTF8

$newOffsets.GetEnumerator() |
    ForEach-Object { [pscustomobject]@{ Path = $_.Key; Offset = $_.Value } } |
    Export-Csv -Path $OffsetFile -NoTypeInformation -Encoding UTF8

# ======================= ФОРМИРОВАНИЕ ban.txt =======================

$manual = @()
if (Test-Path $ManualFile) {
    $manual = Get-Content $ManualFile |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}((/\d{1,2})|(-\d{1,3}(\.\d{1,3}){3}))?$' }
}

$all = @(@($manual) + @($banned.Keys) | Sort-Object -Unique)

# Атомарная замена: FortiGate никогда не скачает недописанный файл
$tmp = "$BanFile.tmp"
Set-Content -Path $tmp -Value $all -Encoding Ascii
Move-Item -Path $tmp -Destination $BanFile -Force

$duration = [int]((Get-Date) - $startTime).TotalSeconds
Write-Log ("Файлов: {0}; прочитано: {1:N1} МБ; неудачных попыток: {2}; новых банов: {3}; снято банов: {4}; предупреждений: {5}; в ban.txt: {6} (ручных {7}, автоматических {8}); время: {9} с" -f `
    $filesCount, ($bytesRead / 1MB), $failCount, $newBans, $expired.Count, $alerts, $all.Count, @($manual).Count, $banned.Count, $duration)
