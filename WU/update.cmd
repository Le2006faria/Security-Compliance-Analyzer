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
powershell -Command "$machineName = (hostname); if (Get-HotFix) { Get-HotFix | Where-Object {($_.InstalledOn -ge [datetime]::Parse('%startDate%')) -and ($_.InstalledOn -le [datetime]::Parse('%endDate%')) -and ($_.Description -like '*HotFix*')} | Sort-Object InstalledOn | Select-Object @{Name='Data';Expression={$_.InstalledOn.ToString('yyyy-MM-dd HH:mm:ss')}}, @{Name='Máquina';Expression={$machineName}}, @{Name='Nome';Expression={$_.Description}}, @{Name='Versão';Expression={$_.HotFixID}}, @{Name='Situação';Expression={if ($_.InstalledOn) {'Concluída'} else {'Atrasada'}}} | Export-Csv -Path C:\temp\%hostName%\hotfix_updates.csv -NoTypeInformation -Encoding UTF8; Write-Host 'HotFixes processados com sucesso.' } else { Write-Host 'Nenhum HotFix encontrado.' }"
if %ERRORLEVEL% neq 0 (
    call :log_error "HotFixes" "Erro ao buscar atualizações de HotFixes"
) else (
    echo O comando do hotFixes foi processado com sucesso.
)
echo -

REM Busca de Drivers
powershell -Command "$machineName = (hostname); $logName = 'Win32_PnPSignedDriver'; if (Get-WmiObject -Class $logName) { Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DriverDate -ge '%startDate%' -and $_.DriverDate -le '%endDate%' } | Sort-Object DriverDate | Select-Object @{Name='Data';Expression={([Management.ManagementDateTimeConverter]::ToDateTime($_.DriverDate)).ToString('yyyy-MM-dd HH:mm:ss')}}, @{Name='Máquina';Expression={$machineName}}, @{Name='Nome';Expression={$_.DeviceName}}, @{Name='Versão';Expression={$_.DriverVersion}}, @{Name='Situação';Expression={if ($_.DriverDate) {'Concluída'} elseif ($_.Status -eq 'Pending') {'Pendente'} elseif ($_.Status -eq 'InProgress') {'Em Progresso'} elseif ($_.Status -eq 'Failed') {'Falhou'} elseif ($_.Status -eq 'Canceled') {'Cancelada'} elseif ($_.Status -eq 'RebootRequired') {'Aguardando Reinicialização'} else {'Atrasada'}}} | Export-Csv -Path C:\temp\%hostname%\driver_updates.csv -NoTypeInformation -Encoding UTF8; Write-Host 'Drivers processados com sucesso.' } else { Write-Host 'Nenhum dado encontrado para drivers.' }"
if %ERRORLEVEL% neq 0 (
    call :log_error "Drivers" "Erro ao buscar atualizações de Drivers"
) else (
    echo O comando do Drivers foi processado com sucesso.
)
echo -

REM Busca de Logs do Windows Defender (Antivírus)
powershell -Command "$machineName = (hostname); $logName = 'Microsoft-Windows-Windows Defender/Operational'; try { $logExists = Get-WinEvent -ListLog $logName -ErrorAction Stop; if ($logExists) { Get-WinEvent -LogName $logName | Where-Object {($_.Id -eq 2000 -or $_.Id -eq 2001) -and ($_.TimeCreated -ge [datetime]::Parse('%startDate%') -and $_.TimeCreated -le [datetime]::Parse('%endDate%'))} | Sort-Object TimeCreated | Select-Object @{Name='Data';Expression={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, @{Name='Máquina';Expression={$machineName}}, @{Name='Nome';Expression={'Windows Defender'}}, @{Name='Versão';Expression={$_.'Id'}}, @{Name='Situação';Expression={if ($_.Id -eq 2000) {'Concluída'} elseif ($_.Id -eq 2001) {'Incompleta'} else {'Indefinida'}}} | Export-Csv -Path C:\temp\%hostName%\defender_updates.csv -NoTypeInformation -Encoding UTF8; Write-Output 'Logs do Windows Defender processados com sucesso.'; } else { Write-Output 'Log do Windows Defender não encontrado.'; } } catch { Write-Output 'Erro ao acessar o log do Windows Defender.';}"
if %ERRORLEVEL% neq 0 (
    call :log_error "Windows Defender" "Erro ao buscar atualizações de Windows Defender"
) else (
    echo O comando do Windows Defender foi processado com sucesso.
)
echo -

REM Busca de Atualizações do Windows Update via WMI
powershell -Command "$machineName = (hostname); if (Get-WmiObject -Class Win32_QuickFixEngineering) { Get-WmiObject -Class Win32_QuickFixEngineering | Where-Object {($_.InstalledOn -ge [datetime]::Parse('%startDate%')) -and ($_.InstalledOn -le [datetime]::Parse('%endDate%')) -and ($_.Description -like '*Update*')} | Sort-Object InstalledOn | Select-Object @{Name='Data';Expression={$_.InstalledOn.ToString('yyyy-MM-dd HH:mm:ss')}}, @{Name='Máquina';Expression={$machineName}}, @{Name='Nome';Expression={$_.Description}}, @{Name='Versão';Expression={$_.HotFixID}}, @{Name='Situação';Expression={if ($_.InstalledOn) {'Concluída'} else {'Atrasada'}}} | Export-Csv -Path C:\temp\%hostName%\windows_update.csv -NoTypeInformation -Encoding UTF8; Write-Host 'Windows Update processado com sucesso.' } else { Write-Host 'Nenhum dado encontrado para Windows Update.' }"
if %ERRORLEVEL% neq 0 (
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
