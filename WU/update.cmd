@echo off
cls
setlocal enabledelayedexpansion

REM Ajuste para garantir que o console use UTF-8
chcp 65001

echo.
echo =======================================================================
echo Script para Armazenar todas as atualizacoes presentes no computador
echo =======================================================================
echo.

REM Pergunta ao usuário o intervalo de datas
:START
echo Digite a data inicial (yyyy-MM-dd):
set /p startDate=

echo Digite a data final (yyyy-MM-dd):
set /p endDate=

REM Converte as datas para o formato YYYYMMDD para comparação
set startDateNum=%startDate:~0,4%%startDate:~5,2%%startDate:~8,2%
set endDateNum=%endDate:~0,4%%endDate:~5,2%%endDate:~8,2%

REM Verifica se a data inicial é anterior à data final
if %startDateNum% geq %endDateNum% (
    echo A data inicial deve ser anterior à data final. Tente novamente.
    goto START
)

REM Pega o dia, mês e ano da data inicial
set dayStart=%startDate:~8,2%
set monthStart=%startDate:~5,2%
set yearStart=%startDate:~0,4%

REM Pega o dia, mês e ano da data final
set dayEnd=%endDate:~8,2%
set monthEnd=%endDate:~5,2%
set yearEnd=%endDate:~0,4%

REM Mapeia o mês para o formato abreviado (substituindo os números diretamente)
set "months=Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec"
set monthNameStart=  
set monthNameEnd=  

REM Corrige o mapeamento diretamente, sem precisar de formatação extra
if "%monthStart%"=="01" set monthNameStart=Jan
if "%monthStart%"=="02" set monthNameStart=Feb
if "%monthStart%"=="03" set monthNameStart=Mar
if "%monthStart%"=="04" set monthNameStart=Apr
if "%monthStart%"=="05" set monthNameStart=May
if "%monthStart%"=="06" set monthNameStart=Jun
if "%monthStart%"=="07" set monthNameStart=Jul
if "%monthStart%"=="08" set monthNameStart=Aug
if "%monthStart%"=="09" set monthNameStart=Sep
if "%monthStart%"=="10" set monthNameStart=Oct
if "%monthStart%"=="11" set monthNameStart=Nov
if "%monthStart%"=="12" set monthNameStart=Dec

if "%monthEnd%"=="01" set monthNameEnd=Jan
if "%monthEnd%"=="02" set monthNameEnd=Feb
if "%monthEnd%"=="03" set monthNameEnd=Mar
if "%monthEnd%"=="04" set monthNameEnd=Apr
if "%monthEnd%"=="05" set monthNameEnd=May
if "%monthEnd%"=="06" set monthNameEnd=Jun
if "%monthEnd%"=="07" set monthNameEnd=Jul
if "%monthEnd%"=="08" set monthNameEnd=Aug
if "%monthEnd%"=="09" set monthNameEnd=Sep
if "%monthEnd%"=="10" set monthNameEnd=Oct
if "%monthEnd%"=="11" set monthNameEnd=Nov
if "%monthEnd%"=="12" set monthNameEnd=Dec

REM Cria as variáveis de data no formato que o MSRT usa
set novaDataStart=%monthNameStart% %dayStart% %yearStart%
set novaDataEnd=%monthNameEnd% %dayEnd% %yearEnd%

REM Adiciona o nome do dia da semana à data, com dia em inglês (forçado pelo parâmetro -Culture en-US)
for /f "tokens=1" %%A in ('powershell -Command "[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'; Get-Date '%novaDataStart%' -Format 'ddd'"') do set weekdayStart=%%A
for /f "tokens=1" %%A in ('powershell -Command "[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'; Get-Date '%novaDataEnd%' -Format 'ddd'"') do set weekdayEnd=%%A

REM Agora a data estará no formato completo: Mon Jan 01 00:00:00 2024
REM Coloca o nome do dia da semana (em inglês) no início da data e coloca a hora no final
echo .
set novaDataStart=%weekdayStart% %novaDataStart% 00:00:00
set novaDataEnd=%weekdayEnd% %novaDataEnd% 00:00:00

REM Ajusta a ordem da data para que o ano apareça depois da hora
set novaDataStart=%weekdayStart% %monthNameStart% %dayStart% 00:00:00 %yearStart%
set novaDataEnd=%weekdayEnd% %monthNameEnd% %dayEnd% 00:00:00 %yearEnd%

REM Exibe a data convertida para verificação
echo Data inicial convertida: %novaDataStart%
echo Data final convertida: %novaDataEnd%

REM Obtém o nome do computador (host)
for /f "tokens=*" %%a in ('hostname') do set hostName=%%a

REM Cria o diretório C:\temp\%hostName% caso não exista
if not exist C:\temp\%hostName% (
    mkdir C:\temp\%hostName%
)

REM Inicializa arquivo final dentro da pasta do host
echo Data,Máquina,Nome,Versão,Situação > C:\temp\%hostName%\all_updates.csv > nul 2>&1

REM Variável para verificar se o arquivo de log será criado
set hasErrors=0

REM Executa as consultas no PowerShell e exporta para CSV
echo.

echo -
REM Busca de HotFixes
powershell -Command "if (-not (Test-Path 'C:\temp\%hostName%')) { New-Item -ItemType Directory -Path 'C:\temp\%hostName%' | Out-Null }; $filePath = 'C:\temp\%hostName%\hotfix_updates.csv'; $logFile = 'C:\temp\%hostName%\resultados_busca.log'; if (Test-Path $filePath) { Remove-Item $filePath -Force }; @('Data,Máquina,Fonte,Versão,Situação') | Out-File -FilePath $filePath -Encoding UTF8; '--- Início da execução: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Out-File -FilePath $logFile -Append; try { $hotFixes = Get-HotFix | Where-Object { ($_.InstalledOn -ge [datetime]::Parse('%startDate%')) -and ($_.InstalledOn -le [datetime]::Parse('%endDate%')) -and ($_.Description -like '*HotFix*') } | Sort-Object InstalledOn | Select-Object @{Name='Data';Expression={$_.InstalledOn.ToString('yyyy-MM-dd HH:mm:ss')}}, @{Name='Máquina';Expression={(hostname)}}, @{Name='Fonte';Expression={'HotFix'}}, @{Name='Versão';Expression={$_.HotFixID}}, @{Name='Situação';Expression={if ($_.InstalledOn -ne $null -and $_.InstalledOn -le (Get-Date)) {'Concluída'} else {'Indefinida'}}}; if ($hotFixes) { $hotFixes | Export-Csv -Path $filePath -NoTypeInformation -Append -Encoding UTF8; 'HotFixes processados com sucesso.' | Out-File -FilePath $logFile -Append } else { 'Nenhum HotFix encontrado no intervalo de datas especificado.' | Out-File -FilePath $logFile -Append } } catch { 'Erro ao acessar informações de HotFixes: ' + $_.Exception.Message | Out-File -FilePath $logFile -Append }"; 
if not exist C:\temp\%hostname%\hotfix_updates.csv (
    echo Arquivo hotfix_updates.csv não foi criado. >> C:\temp\%hostname%\errors.log
    call :log_error "HotFixes" "Erro ao buscar atualizações de HotFixes"
) else (
    echo O comando do HotFixes foi processado com sucesso.
)
echo -

REM Busca de Drivers
powershell -Command "if (-not (Test-Path 'C:\temp\%hostName%')) { New-Item -ItemType Directory -Path 'C:\temp\%hostName%' | Out-Null }; $filePath = 'C:\temp\%hostName%\driver_updates.csv'; $logFile = 'C:\temp\%hostName%\resultados_busca.log'; if (Test-Path $filePath) { Remove-Item $filePath -Force }; @('Data,Máquina,Fonte,Versão,Situação') | Out-File -FilePath $filePath -Encoding UTF8; '--- Início da execução: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Out-File -FilePath $logFile -Append; try { $drivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DriverDate -ge '%startDate%' -and $_.DriverDate -le '%endDate%' } | Sort-Object DriverDate | Select-Object @{Name='Data';Expression={([Management.ManagementDateTimeConverter]::ToDateTime($_.DriverDate)).ToString('yyyy-MM-dd HH:mm:ss')}}, @{Name='Máquina';Expression={(hostname)}}, @{Name='Fonte';Expression={'Drivers'}}, @{Name='Versão';Expression={$_.DriverVersion}}, @{Name='Situação';Expression={if ($_.DriverDate) {'Concluída'} else {'Indefinida'}}}; if ($drivers) { $drivers | Export-Csv -Path $filePath -NoTypeInformation -Append -Encoding UTF8; 'Drivers processados com sucesso.' | Out-File -FilePath $logFile -Append } else { 'Nenhum dado encontrado para drivers no intervalo de datas especificado.' | Out-File -FilePath $logFile -Append } } catch { 'Erro ao acessar informações de drivers: ' + $_.Exception.Message | Out-File -FilePath $logFile -Append }"; 
if not exist C:\temp\%hostname%\driver_updates.csv (
    echo Arquivo driver_updates.csv não foi criado. >> C:\temp\%hostname%\errors.log
    call :log_error "Drivers" "Erro ao buscar atualizações de Drivers"
) else (
    echo O comando do Drivers foi processado com sucesso.
)
echo -

REM Busca de Logs do Windows Defender (Antivírus)
powershell -Command "if (-not (Test-Path 'C:\temp\%hostName%')) { New-Item -ItemType Directory -Path 'C:\temp\%hostName%' | Out-Null }; $filePath = 'C:\temp\%hostName%\defender_updates.csv'; $logFile = 'C:\temp\%hostName%\resultados_busca.log'; if (Test-Path $filePath) { Remove-Item $filePath -Force }; @('Data,Máquina,Fonte,Versão,Situação') | Out-File -FilePath $filePath -Encoding UTF8; '--- Início da execução: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Out-File -FilePath $logFile -Append; try { $logExists = Get-WinEvent -ListLog 'Microsoft-Windows-Windows Defender/Operational' -ErrorAction SilentlyContinue; if ($logExists -and $logExists.Count -gt 0) { $events = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' | Where-Object { ($_.Id -eq 2000 -or $_.Id -eq 2001) -and ($_.TimeCreated -ge [datetime]::Parse('%startDate%') -and $_.TimeCreated -le [datetime]::Parse('%endDate%')) } | Sort-Object TimeCreated | Select-Object @{Name='Data';Expression={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, @{Name='Máquina';Expression={(hostname)}}, @{Name='Fonte';Expression={'Windows Defender'}}, @{Name='Versão';Expression={$_.'Id'}}, @{Name='Situação';Expression={if ($_.Id -eq 2000) {'Concluída'} elseif ($_.Id -eq 2001) {'Incompleta'} else {'Indefinida'}}}; if ($events) { $events | Export-Csv -Path $filePath -NoTypeInformation -Append -Encoding UTF8; 'Logs do Windows Defender processados com sucesso.' | Out-File -FilePath $logFile -Append } else { 'Nenhum dado encontrado para o Windows Defender no intervalo de datas especificado.' | Out-File -FilePath $logFile -Append } } else { 'Log do Windows Defender não encontrado ou vazio.' | Out-File -FilePath $logFile -Append } } catch { 'Erro ao acessar o log do Windows Defender: ' + $_.Exception.Message | Out-File -FilePath $logFile -Append }"; 
if not exist C:\temp\%hostName%\defender_updates.csv (
    echo Arquivo defender_updates.csv não foi criado. >> C:\temp\%hostName%\errors.log
    call :log_error "Windows Defender" "Erro ao buscar atualizações de Windows Defender"
) else (
    echo O comando do Windows Defender foi processado com sucesso.
)
echo -

REM Busca de Atualizações do Windows Update via WMI
powershell -Command "if (-not (Test-Path 'C:\temp\%hostName%')) { New-Item -ItemType Directory -Path 'C:\temp\%hostName%' | Out-Null }; $filePath = 'C:\temp\%hostName%\windows_update.csv'; $logFile = 'C:\temp\%hostName%\resultados_busca.log'; if (Test-Path $filePath) { Remove-Item $filePath -Force }; @('Data,Máquina,Fonte,Versão,Situação') | Out-File -FilePath $filePath -Encoding UTF8; '--- Início da execução: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Out-File -FilePath $logFile -Append; try { $updates = Get-WmiObject -Class Win32_QuickFixEngineering | Where-Object { ($_.InstalledOn -ge [datetime]::Parse('%startDate%')) -and ($_.InstalledOn -le [datetime]::Parse('%endDate%')) -and ($_.Description -like '*Update*') } | Sort-Object InstalledOn | Select-Object @{Name='Data';Expression={$_.InstalledOn.ToString('yyyy-MM-dd HH:mm:ss')}}, @{Name='Máquina';Expression={(hostname)}}, @{Name='Fonte';Expression={'Windows Update'}}, @{Name='Versão';Expression={$_.HotFixID}}, @{Name='Situação';Expression={if ($_.InstalledOn) {'Concluída'} else {'Indefinida'}}}; if ($updates) { $updates | Export-Csv -Path $filePath -NoTypeInformation -Append -Encoding UTF8; 'Windows Update processado com sucesso.' | Out-File -FilePath $logFile -Append } else { 'Nenhum dado encontrado para Windows Update no intervalo de datas especificado.' | Out-File -FilePath $logFile -Append } } catch { 'Erro ao acessar informações de Windows Update: ' + $_.Exception.Message | Out-File -FilePath $logFile -Append }"
if not exist C:\temp\%hostName%\windows_update.csv (
    echo Arquivo windows_update.csv não foi criado. >> C:\temp\%hostName%\errors.log
    call :log_error "Windows Update" "Erro ao buscar atualizações de Windows Update"
) else (
    echo O comando do Windows Update foi processado com sucesso.
)
echo -

REM Busca de Atualizações do Malicious Software Removal
powershell -Command "if (-not (Test-Path 'C:\temp\%hostname%')) { New-Item -ItemType Directory -Path 'C:\temp\%hostname%' | Out-Null }; $filePath = 'C:\temp\%hostname%\malicious_software_updates.csv'; $logFile = 'C:\temp\%hostname%\resultados_busca.log'; if (Test-Path $filePath) { Remove-Item $filePath -Force }; @('Data Início,Máquina,Fonte,Versão,Situação') | Out-File -FilePath $filePath -Encoding UTF8; '--- Início da execução: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Out-File -FilePath $logFile -Append; try { if (-not (Test-Path 'C:\Windows\Debug\mrt.log')) { 'Arquivo mrt.log não encontrado. Nenhuma atualização processada.' | Out-File -FilePath $logFile -Append } else { $logs = Get-Content -Path 'C:\Windows\Debug\mrt.log'; $updates = @(); $currentUpdate = @{ 'Data Início' = $null; 'Máquina' = $null; 'Fonte' = 'Malicious Software Removal Tool'; 'Versão' = $null; 'Situação' = $null }; $startDate = [datetime]::ParseExact('%novaDataStart%', 'ddd MMM dd HH:mm:ss yyyy', [System.Globalization.CultureInfo]::GetCultureInfo('en-US')); foreach ($line in $logs) { if ($line -match '^Started On (.+)$') { $dateStart = $matches[1].Trim(); try { $currentUpdate['Data Início'] = [datetime]::ParseExact($dateStart, 'ddd MMM dd HH:mm:ss yyyy', [System.Globalization.CultureInfo]::GetCultureInfo('en-US')) } catch { $currentUpdate['Data Início'] = $dateStart } } elseif ($line -match '^Microsoft Windows Malicious Software Removal Tool v([\d\.]+)') { $currentUpdate['Versão'] = $matches[1] } elseif ($line -match '(?i)(No infection found|Successfully Submitted Heartbeat Report)') { $currentUpdate['Situação'] = 'Concluída' } elseif ($line -match '(?i)(Error occurred|Scan failed)') { $currentUpdate['Situação'] = 'Falha' }; if ($currentUpdate['Data Início'] -and $currentUpdate['Situação']) { if ($currentUpdate['Data Início'] -ge $startDate) { $currentUpdate['Máquina'] = (hostname); $updates += New-Object PSCustomObject -Property @{ 'Data Início' = $currentUpdate['Data Início']; 'Máquina' = $currentUpdate['Máquina']; 'Fonte' = $currentUpdate['Fonte']; 'Versão' = $currentUpdate['Versão']; 'Situação' = $currentUpdate['Situação'] } } $currentUpdate = @{ 'Data Início' = $null; 'Máquina' = $null; 'Fonte' = 'Malicious Software Removal Tool'; 'Versão' = $null; 'Situação' = $null } }; }; if ($updates.Count -gt 0) { $updates | Export-Csv -Path $filePath -NoTypeInformation -Append -Encoding UTF8; 'Atualizações do MSRT processadas com sucesso.' | Out-File -FilePath $logFile -Append } else { 'Nenhuma atualização do MSRT encontrada no intervalo de datas especificado.' | Out-File -FilePath $logFile -Append } } } catch { 'Erro ao acessar informações de atualizações: ' + $_.Exception.Message | Out-File -FilePath $logFile -Append }"
if not exist C:\temp\%hostName%\malicious_software_updates.csv (
    echo Arquivo malicious_software_updates.csv não foi criado. >> C:\temp\%hostName%\errors.log
    call :log_error "Malicious Software Removal" "Erro ao buscar atualizações de Malicious Software Removal"
) else (
    echo O comando do Malicious Software Removal foi processado com sucesso.
)
echo -

REM Juntando os CSVs em um único arquivo com a codificação UTF-8

REM Primeiramente, copiamos o cabeçalho do primeiro CSV
for /f "tokens=1,2,3,4,5 delims=," %%A in (C:\temp\%hostName%\hotfix_updates.csv) do (
    set firstLine=%%A
    goto nextLine
)
:nextLine
echo !firstLine! > C:\temp\%hostName%\all_updates.csv

REM Copia os dados do arquivo HotFixes
for /f "skip=1 tokens=1,2,3,4,5 delims=," %%A in (C:\temp\%hostName%\hotfix_updates.csv) do (
    echo "%%A"; "%%B"; "%%C"; "%%D"; "%%E" >> C:\temp\%hostName%\all_updates.csv
)

REM Coloca uma linha em branco entre as tabelas
echo. >> C:\temp\%hostName%\all_updates.csv

REM Copia os dados do arquivo Driver Updates
for /f "skip=1 tokens=1,2,3,4,5 delims=," %%A in (C:\temp\%hostName%\driver_updates.csv) do (
   echo "%%A"; "%%B"; "%%C"; "%%D"; "%%E" >> C:\temp\%hostName%\all_updates.csv
)

REM Coloca uma linha em branco entre as tabelas
echo. >> C:\temp\%hostName%\all_updates.csv

REM Copia os dados do arquivo Defender Updates
for /f "skip=1 tokens=1,2,3,4,5 delims=," %%A in (C:\temp\%hostName%\defender_updates.csv) do (
   echo "%%A"; "%%B"; "%%C"; "%%D"; "%%E" >> C:\temp\%hostName%\all_updates.csv
)

REM Coloca uma linha em branco entre as tabelas
echo. >> C:\temp\%hostName%\all_updates.csv

REM Copia os dados do arquivo Windows Update
for /f "skip=1 tokens=1,2,3,4,5 delims=," %%A in (C:\temp\%hostName%\windows_update.csv) do (
   echo "%%A"; "%%B"; "%%C"; "%%D"; "%%E" >> C:\temp\%hostName%\all_updates.csv
)

REM Coloca uma linha em branco entre as tabelas
echo. >> C:\temp\%hostName%\all_updates.csv

REM Copia os dados do arquivo Malicious Software Removal
for /f "skip=1 tokens=1,2,3,4,5 delims=," %%A in (C:\temp\%hostName%\malicious_software_updates.csv) do (
   echo "%%A"; "%%B"; "%%C"; "%%D"; "%%E" >> C:\temp\%hostName%\all_updates.csv
)

REM Coloca uma linha em branco entre as tabelas
echo. >> C:\temp\%hostName%\all_updates.csv

:log_error
set hasErrors=1
if not exist C:\temp\%hostName%\errors.log (
    echo Log de erros gerado em %date% %time% > C:\temp\%hostName%\errors.log
)
echo [ERRO] [%date% %time%] Falha ao executar consulta %1. Detalhes: %2 >> C:\temp\%hostName%\errors.log

echo.
echo Dados exportados para C:\temp\%hostName%\all_updates.csv

echo.
echo =======================================================================
echo Configuracoes de atualizacoes aplicadas.
echo =======================================================================
echo.

pause
