@echo off
cls
setlocal

echo .

echo Verificando o status do servico TermService...

:: Verifica o status do serviço
sc query TermService >nul 2>&1
if %errorlevel% neq 0 (
    echo O servico TermService nao existe.
    goto :end
) else (
    :: Busca pela linha que contém o estado do serviço
    for /f "tokens=3" %%A in ('sc query TermService ^| findstr /I /C:"STATE" /C:"ESTADO"') do (
        if "%%A"=="4" (
            echo O servico TermService esta ativado.
            set "status=ativo"
        ) else if "%%A"=="1" (
            echo O servico TermService esta desativado.
            set "status=inativo"
        ) else (
            echo O estado do servico TermService nao foi identificado corretamente.
            goto :end
        )
    )
)

:: Opção para habilitar ou desabilitar o serviço
set /p choice="Deseja alternar o estado do servico TermService? (S/N): "
if /i "%choice%"=="S" (
    if "%status%"=="ativo" (
        echo Desativando o servico TermService...
        sc stop TermService >nul
        echo O servico TermService foi desativado.
    ) else if "%status%"=="inativo" (
        echo Ativando o servico TermService...
        sc start TermService >nul
        echo O servico TermService foi ativado.
    )
) else (
    echo Nenhuma alteracao foi feita no estado do servico TermService.
)

echo.

echo Verificando o status do servico RemoteRegistry...

:: Verifica se o serviço existe
sc query RemoteRegistry >nul 2>&1
if %errorlevel% neq 0 (
    echo O servico RemoteRegistry nao existe.
    goto :end
) else (
    :: Busca pela linha que contém o estado do serviço
    for /f "tokens=3" %%A in ('sc query RemoteRegistry ^| findstr /I /C:"STATE" /C:"ESTADO"') do (
        if "%%A"=="4" (
            echo O servico RemoteRegistry esta ativado.
            set "status=ativo"
        ) else if "%%A"=="1" (
            echo O servico RemoteRegistry esta desativado.
            set "status=inativo"
        ) else (
            echo O estado do servico RemoteRegistry nao foi identificado corretamente.
            goto :end
        )
    )
)

:: Opção para habilitar ou desabilitar o serviço
set /p choice="Deseja alternar o estado do servico RemoteRegistry? (S/N): "
if /i "%choice%"=="S" (
    if "%status%"=="ativo" (
        echo Desativando o servico RemoteRegistry...
        sc stop RemoteRegistry >nul
        echo O servico RemoteRegistry foi desativado.
    ) else if "%status%"=="inativo" (
        echo Ativando o servico RemoteRegistry...
        sc start RemoteRegistry >nul
        echo O servico RemoteRegistry foi ativado.
    )
) else (
    echo Nenhuma alteracao foi feita no estado do servico RemoteRegistry.
)

echo .

echo Verificando o status do servico WinRM...

:: Verifica se o serviço existe
sc query WinRM >nul 2>&1
if %errorlevel% neq 0 (
    echo O servico WinRM nao existe.
    goto :end
) else (
    :: Busca pela linha que contém o estado do serviço
    for /f "tokens=3" %%A in ('sc query WinRM ^| findstr /I /C:"STATE" /C:"ESTADO"') do (
        if "%%A"=="4" (
            echo O servico WinRM esta ativado.
            set "status=ativo"
        ) else if "%%A"=="1" (
            echo O servico WinRM esta desativado.
            set "status=inativo"
        ) else (
            echo O estado do servico WinRM nao foi identificado corretamente.
            goto :end
        )
    )
)

:: Opção para habilitar ou desabilitar o serviço
set /p choice="Deseja alternar o estado do servico WinRM? (S/N): "
if /i "%choice%"=="S" (
    if "%status%"=="ativo" (
        echo Desativando o servico WinRM...
        sc stop WinRM >nul
        echo O servico WinRM foi desativado.
    ) else if "%status%"=="inativo" (
        echo Ativando o servico WinRM...
        sc start WinRM >nul
        echo O servico WinRM foi ativado.
    )
) else (
    echo Nenhuma alteracao foi feita no estado do servico WinRM.
)

echo .

echo Verificando os perfis de firewall...

:: Função para verificar e alternar o estado de um perfil de firewall
setlocal enabledelayedexpansion

:: Verificar o perfil de firewall Domain
for /f "tokens=*" %%A in ('powershell.exe -Command "(Get-NetFirewallProfile -Name Domain).Enabled"') do (
    set "DomainStatus=%%A"
)
if "%DomainStatus%"=="True" (
    echo O perfil de firewall Domain esta habilitado.
    set "DomainStatus=ativo"
) else (
    echo O perfil de firewall Domain esta desabilitado ou nao existe.
    set "DomainStatus=inativo"
)

set /p choice="Deseja alternar o estado do perfil Domain? (S/N): "
if /i "%choice%"=="S" (
    if "%DomainStatus%"=="ativo" (
        echo Desativando o perfil Domain...
        powershell.exe -Command "Set-NetFirewallProfile -Name Domain -Enabled False"
        echo O perfil Domain foi desativado.
    ) else (
        echo Ativando o perfil Domain...
        powershell.exe -Command "Set-NetFirewallProfile -Name Domain -Enabled True"
        echo O perfil Domain foi ativado.
    )
)

echo.

:: Verificar o perfil de firewall Public
for /f "tokens=*" %%A in ('powershell.exe -Command "(Get-NetFirewallProfile -Name Public).Enabled"') do (
    set "PublicStatus=%%A"
)
if "%PublicStatus%"=="True" (
    echo O perfil de firewall Public esta habilitado.
    set "PublicStatus=ativo"
) else (
    echo O perfil de firewall Public esta desabilitado ou nao existe.
    set "PublicStatus=inativo"
)

set /p choice="Deseja alternar o estado do perfil Public? (S/N): "
if /i "%choice%"=="S" (
    if "%PublicStatus%"=="ativo" (
        echo Desativando o perfil Public...
        powershell.exe -Command "Set-NetFirewallProfile -Name Public -Enabled False"
        echo O perfil Public foi desativado.
    ) else (
        echo Ativando o perfil Public...
        powershell.exe -Command "Set-NetFirewallProfile -Name Public -Enabled True"
        echo O perfil Public foi ativado.
    )
)

echo.

:: Verificar o perfil de firewall Private
for /f "tokens=*" %%A in ('powershell.exe -Command "(Get-NetFirewallProfile -Name Private).Enabled"') do (
    set "PrivateStatus=%%A"
)
if "%PrivateStatus%"=="True" (
    echo O perfil de firewall Private esta habilitado.
    set "PrivateStatus=ativo"
) else (
    echo O perfil de firewall Private esta desabilitado ou nao existe.
    set "PrivateStatus=inativo"
)

set /p choice="Deseja alternar o estado do perfil Private? (S/N): "
if /i "%choice%"=="S" (
    if "%PrivateStatus%"=="ativo" (
        echo Desativando o perfil Private...
        powershell.exe -Command "Set-NetFirewallProfile -Name Private -Enabled False"
        echo O perfil Private foi desativado.
    ) else (
        echo Ativando o perfil Private...
        powershell.exe -Command "Set-NetFirewallProfile -Name Private -Enabled True"
        echo O perfil Private foi ativado.
    )
)

echo .

echo Verificando o valor da chave de registro UseLogonCredential...

:: Verifica se a chave existe
reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential >nul 2>&1
for %errorlevel%==0 (
    echo A chave de registro UseLogonCredential já existe.

    :: Exibe o valor atual da chave
    for /f "tokens=3" %%A in ('reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential') do (
        echo O valor atual da chave é: %%A
        if "%%A"=="0x0" (
            echo A chave está desativada (valor=0).
        ) else (
            echo Cuidado! A chave está ativada (valor=1), o que pode expor senhas na memória.
        )
    )

    :: Pergunta se deseja alterar o valor
    set /p choice="Deseja alterar o valor da chave de registro UseLogonCredential? (S/N): "
    if /i "%choice%"=="S" (
        set /p newValue="Digite o valor desejado para a chave (0 para desativar, 1 para ativar): "
        
        if "%newValue%"=="0" (
            reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
            echo A chave UseLogonCredential foi desativada (valor=0).
        ) else if "%newValue%"=="1" (
            reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f
            echo A chave UseLogonCredential foi ativada (valor=1).
        ) else (
            echo Valor inválido! Nenhuma alteração foi feita.
        )
    ) else (
        echo Nenhuma alteração foi feita no valor da chave de registro UseLogonCredential.
    )

) else (
    echo A chave de registro UseLogonCredential não existe ou está com valor indefinido.
    
    :: Pergunta se deseja criar a chave
    set /p createChoice="Deseja criar a chave UseLogonCredential? (S/N): "
    if /i "%createChoice%"=="S" (
        set /p newValue="Digite o valor desejado para a chave (0 para desativar, 1 para ativar): "
        
        if "%newValue%"=="0" (
            reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
            echo A chave UseLogonCredential foi criada com valor 0 (desativada).
        ) else if "%newValue%"=="1" (
            reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f
            echo A chave UseLogonCredential foi criada com valor 1 (ativada).
        ) else (
            echo Valor inválido! A chave não foi criada.
        )
    ) else (
        echo A chave de registro UseLogonCredential não foi criada.
    )
)

:end
pause
