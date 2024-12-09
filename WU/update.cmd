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

REM Converte as datas para formato numérico (yyyyMMdd) para comparação
set startDateNum=%startDate:~0,4%%startDate:~5,2%%startDate:~8,2%
set endDateNum=%endDate:~0,4%%endDate:~5,2%%endDate:~8,2%

REM Verifica se a data inicial é anterior à data final
if !startDateNum! geq !endDateNum! (
    echo A data inicial deve ser anterior à data final. Tente novamente.
    goto START
)

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
powershell -Command "$machineName = (hostname); $filePath = 'C:\temp\%hostName%\hotfix_updates.csv'; $logFile = 'C:\temp\%hostName%\resultados_busca.log'; try { if (-not (Test-Path 'C:\temp\%hostName%')) { New-Item -ItemType Directory -Path 'C:\temp\%hostName%' | Out-Null; } if (-not (Test-Path $filePath)) { @('Data,Máquina,Fonte,Versão,Situação') | Out-File -FilePath $filePath -Encoding UTF8; } '--- Início da execução: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Out-File -FilePath $logFile -Append; $hotFixes = Get-HotFix | Where-Object {($_.InstalledOn -ge [datetime]::Parse('%startDate%')) -and ($_.InstalledOn -le [datetime]::Parse('%endDate%')) -and ($_.Description -like '*HotFix*')} | Sort-Object InstalledOn | Select-Object @{Name='Data';Expression={$_.InstalledOn.ToString('yyyy-MM-dd HH:mm:ss')}}, @{Name='Máquina';Expression={$machineName}}, @{Name='Fonte';Expression={'HotFix'}}, @{Name='Versão';Expression={$_.HotFixID}}, @{Name='Situação';Expression={if ($_.InstalledOn -ne $null -and $_.InstalledOn -le (Get-Date)) {'Concluída'} else {'Indefinida'}}}; if ($hotFixes) { $hotFixes | Export-Csv -Path $filePath -NoTypeInformation -Append -Encoding UTF8; 'HotFixes processados com sucesso.' | Out-File -FilePath $logFile -Append } else { 'Nenhum HotFix encontrado no intervalo de datas especificado.' | Out-File -FilePath $logFile -Append; } } catch { 'Erro ao acessar informações de HotFixes: ' + $_.Exception.Message | Out-File -FilePath $logFile -Append; }"
if not exist C:\temp\%hostname%\hotfix_updates.csv (
    echo Arquivo hotfix_updates.csv não foi criado. >> C:\temp\%hostname%\errors.log
    call :log_error "HotFixes" "Erro ao buscar atualizações de HotFixes"
) else (
    echo O comando do HotFixes foi processado com sucesso.
)
echo -

REM Busca de Drivers
powershell -Command "$machineName = (hostname); $filePath = 'C:\temp\%hostName%\driver_updates.csv'; $logFile = 'C:\temp\%hostName%\resultados_busca.log'; try { if (-not (Test-Path 'C:\temp\%hostName%')) { New-Item -ItemType Directory -Path 'C:\temp\%hostName%' | Out-Null; } if (-not (Test-Path $filePath)) { @('Data,Máquina,Fonte,Versão,Situação') | Out-File -FilePath $filePath -Encoding UTF8; } '--- Início da execução: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Out-File -FilePath $logFile -Append; $drivers = Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DriverDate -ge '%startDate%' -and $_.DriverDate -le '%endDate%' } | Sort-Object DriverDate | Select-Object @{Name='Data';Expression={([Management.ManagementDateTimeConverter]::ToDateTime($_.DriverDate)).ToString('yyyy-MM-dd HH:mm:ss')}}, @{Name='Máquina';Expression={$machineName}}, @{Name='Fonte';Expression={'Drivers'}}, @{Name='Versão';Expression={$_.DriverVersion}}, @{Name='Situação';Expression={if ($_.DriverDate) {'Concluída'} else {'Indefinida'}}}; if ($drivers) { $drivers | Export-Csv -Path $filePath -NoTypeInformation -Append -Encoding UTF8; 'Drivers processados com sucesso.' | Out-File -FilePath $logFile -Append } else { 'Nenhum dado encontrado para drivers no intervalo de datas especificado.' | Out-File -FilePath $logFile -Append; } } catch { 'Erro ao acessar informações de drivers: ' + $_.Exception.Message | Out-File -FilePath $logFile -Append; }"
if not exist C:\temp\%hostname%\driver_updates.csv (
    echo Arquivo driver_updates.csv não foi criado. >> C:\temp\%hostname%\errors.log
    call :log_error "Drivers" "Erro ao buscar atualizações de Drivers"
) else (
    echo O comando do Drivers foi processado com sucesso.
)
echo -

REM Busca de Logs do Windows Defender (Antivírus)
powershell -Command "$machineName = (hostname); $logName = 'Microsoft-Windows-Windows Defender/Operational'; $filePath = 'C:\temp\%hostName%\defender_updates.csv'; $logFile = 'C:\temp\%hostName%\resultados_busca.log'; try { if (-not (Test-Path 'C:\temp\%hostName%')) { New-Item -ItemType Directory -Path 'C:\temp\%hostName%' | Out-Null; } if (-not (Test-Path $filePath)) { @('Data,Máquina,Fonte,Versão,Situação') | Out-File -FilePath $filePath -Encoding UTF8; } '--- Início da execução: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Out-File -FilePath $logFile -Append; $logExists = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue; if ($logExists -and $logExists.Count -gt 0) { $events = Get-WinEvent -LogName $logName | Where-Object {($_.Id -eq 2000 -or $_.Id -eq 2001) -and ($_.TimeCreated -ge [datetime]::Parse('%startDate%') -and $_.TimeCreated -le [datetime]::Parse('%endDate%'))} | Sort-Object TimeCreated | Select-Object @{Name='Data';Expression={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, @{Name='Máquina';Expression={$machineName}}, @{Name='Fonte';Expression={'Windows Defender'}}, @{Name='Versão';Expression={$_.'Id'}}, @{Name='Situação';Expression={if ($_.Id -eq 2000) {'Concluída'} elseif ($_.Id -eq 2001) {'Incompleta'} else {'Indefinida'}}}; if ($events) { $events | Export-Csv -Path $filePath -NoTypeInformation -Append -Encoding UTF8; 'Logs do Windows Defender processados com sucesso.' | Out-File -FilePath $logFile -Append } else { 'Nenhum dado encontrado para o Windows Defender no intervalo de datas especificado.' | Out-File -FilePath $logFile -Append; } } else { 'Log do Windows Defender não encontrado ou vazio.' | Out-File -FilePath $logFile -Append; } } catch { 'Erro ao acessar o log do Windows Defender: ' + $_.Exception.Message | Out-File -FilePath $logFile -Append; }"
if not exist C:\temp\%hostName%\defender_updates.csv (
    echo Arquivo defender_updates.csv não foi criado. >> C:\temp\%hostName%\errors.log
    call :log_error "Windows Defender" "Erro ao buscar atualizações de Windows Defender"
) else (
    echo O comando do Windows Defender foi processado com sucesso.
)
echo -

REM Busca de Atualizações do Windows Update via WMI
powershell -Command "$machineName = (hostname); $filePath = 'C:\temp\%hostName%\windows_update.csv'; $logFile = 'C:\temp\%hostName%\resultados_busca.log'; try { if (-not (Test-Path 'C:\temp\%hostName%')) { New-Item -ItemType Directory -Path 'C:\temp\%hostName%' | Out-Null; } if (-not (Test-Path $filePath)) { @('Data,Máquina,Fonte,Versão,Situação') | Out-File -FilePath $filePath -Encoding UTF8; } '--- Início da execução: ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Out-File -FilePath $logFile -Append; $updates = Get-WmiObject -Class Win32_QuickFixEngineering | Where-Object {($_.InstalledOn -ge [datetime]::Parse('%startDate%')) -and ($_.InstalledOn -le [datetime]::Parse('%endDate%')) -and ($_.Description -like '*Update*')} | Sort-Object InstalledOn | Select-Object @{Name='Data';Expression={$_.InstalledOn.ToString('yyyy-MM-dd HH:mm:ss')}}, @{Name='Máquina';Expression={$machineName}}, @{Name='Fonte';Expression={'Windows Update'}}, @{Name='Versão';Expression={$_.HotFixID}}, @{Name='Situação';Expression={if ($_.InstalledOn) {'Concluída'} else {'Indefinida'}}}; if ($updates) { $updates | Export-Csv -Path $filePath -NoTypeInformation -Append -Encoding UTF8; 'Windows Update processado com sucesso.' | Out-File -FilePath $logFile -Append } else { 'Nenhum dado encontrado para Windows Update no intervalo de datas especificado.' | Out-File -FilePath $logFile -Append; } } catch { 'Erro ao acessar informações de Windows Update: ' + $_.Exception.Message | Out-File -FilePath $logFile -Append; }"
if not exist C:\temp\%hostName%\windows_update.csv (
    echo Arquivo windows_update.csv não foi criado. >> C:\temp\%hostName%\errors.log
    call :log_error "Windows Update" "Erro ao buscar atualizações de Windows Update"
) else (
    echo O comando do Windows Update foi processado com sucesso.
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
