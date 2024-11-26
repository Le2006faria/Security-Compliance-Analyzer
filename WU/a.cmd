@echo off
cls
setlocal enabledelayedexpansion

REM Ajuste para garantir que o console use UTF-8
chcp 65001

echo =====================================================
echo Script para Armazenar todas as atualizacoes presentes no computador
echo =====================================================

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

REM Cria o diretório C:\temp caso não exista
if not exist C:\temp (
    mkdir C:\temp
)

REM Executa as consultas no PowerShell e exporta para CSV

REM Busca de HotFixes
powershell -Command "Get-HotFix | Where-Object {($_.InstalledOn -ge '%startDate%') -and ($_.InstalledOn -le '%endDate%')} | Select-Object @{Name='Nome';Expression={$_.Description}}, @{Name='Versão';Expression={$_.HotFixID}}, @{Name='Data';Expression={$_.InstalledOn}}, @{Name='Situação';Expression={if ($_.InstalledOn) {'Concluída'} elseif ($_.Status -eq 'Pending') {'Pendente'} elseif ($_.Status -eq 'InProgress') {'Em Progresso'} elseif ($_.Status -eq 'Failed') {'Falhou'} elseif ($_.Status -eq 'Canceled') {'Cancelada'} elseif ($_.Status -eq 'RebootRequired') {'Aguardando Reinicialização'} else {'Atrasada'}}} | Export-Csv -Path C:\temp\hotfix_updates.csv -NoTypeInformation -Encoding UTF8"

REM Busca de Drivers
powershell -Command "Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DriverDate -ge '%startDate%' -and $_.DriverDate -le '%endDate%' } | Select-Object @{Name='Nome';Expression={$_.DeviceName}}, @{Name='Versão';Expression={$_.DriverVersion}}, @{Name='Data';Expression={([Management.ManagementDateTimeConverter]::ToDateTime($_.DriverDate)).ToString('yyyy-MM-dd HH:mm:ss')}}, @{Name='Situação';Expression={if ($_.DriverDate) {'Concluída'} elseif ($_.Status -eq 'Pending') {'Pendente'} elseif ($_.Status -eq 'InProgress') {'Em Progresso'} elseif ($_.Status -eq 'Failed') {'Falhou'} elseif ($_.Status -eq 'Canceled') {'Cancelada'} elseif ($_.Status -eq 'RebootRequired') {'Aguardando Reinicialização'} else {'Atrasada'}}} | Export-Csv -Path C:\temp\driver_updates.csv -NoTypeInformation -Encoding UTF8"

REM Busca de Logs do Windows Defender (Antivírus)
powershell -Command "Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' | Where-Object {($_.Id -eq 2000 -or $_.Id -eq 2001) -and ($_.TimeCreated -ge '%startDate%' -and $_.TimeCreated -le '%endDate%')} | Select-Object @{Name='Nome';Expression={'Windows Defender'}}, @{Name='Versão';Expression={$_.'Id'}}, @{Name='Data';Expression={$_.TimeCreated}}, @{Name='Situação';Expression={if ($_.Id -eq 2000) {'Concluída'} elseif ($_.Id -eq 2001) {'Incompleta'} elseif ($_.Status -eq 'Pending') {'Pendente'} elseif ($_.Status -eq 'InProgress') {'Em Progresso'} elseif ($_.Status -eq 'Failed') {'Falhou'} elseif ($_.Status -eq 'Canceled') {'Cancelada'} elseif ($_.Status -eq 'RebootRequired') {'Aguardando Reinicialização'} else {'Atrasada'}}} | Export-Csv -Path C:\temp\defender_updates.csv -NoTypeInformation -Encoding UTF8"

REM Juntando os CSVs em um único arquivo com a codificação UTF-8

REM Primeiramente, copiamos o cabeçalho do primeiro CSV
for /f "tokens=1,2,3* delims=," %%A in (C:\temp\hotfix_updates.csv) do (
    set firstLine=%%A
    goto nextLine
)
:nextLine
echo !firstLine! > C:\temp\all_updates.csv

REM Copia os dados do arquivo HotFixes
for /f "skip=4 tokens=1,2,3,4 delims=," %%A in (C:\temp\hotfix_updates.csv) do (
    echo %%A; %%B; %%C; %%D >> C:\temp\all_updates.csv
)

REM Coloca uma linha em branco entre as tabelas
echo. >> C:\temp\all_updates.csv

REM Copia os dados do arquivo Driver Updates
for /f "skip=1 tokens=1,2,3,4 delims=," %%A in (C:\temp\driver_updates.csv) do (
    echo %%A; %%B; %%C; %%D >> C:\temp\all_updates.csv
)

REM Coloca uma linha em branco entre as tabelas
echo. >> C:\temp\all_updates.csv

REM Copia os dados do arquivo Defender Updates
for /f "skip=1 tokens=1,2,3,4 delims=," %%A in (C:\temp\defender_updates.csv) do (
    echo %%A; %%B; %%C; %%D >> C:\temp\all_updates.csv
)

REM Coloca uma linha em branco entre as tabelas
echo. >> C:\temp\all_updates.csv

echo Dados exportados para C:\temp\all_updates.csv

echo =====================================================
echo Configuracoes de atualizacoes aplicadas.
echo =====================================================
