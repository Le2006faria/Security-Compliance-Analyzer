@echo off
cls
setlocal

echo .

echo Verificando o status do servico TermService...

:: Verifica o status do serviço
sc query TermService >nul 2>&1
if %errorlevel% neq 0 (
    echo O servico TermService nao existe.
) else (
    :: Busca pela linha que contém o estado do serviço
    for /f "tokens=3" %%A in ('sc query TermService ^| findstr /I /C:"STATE" /C:"ESTADO"') do (
        if "%%A"=="4" (
            echo O servico TermService esta ativado.
        ) else if "%%A"=="1" (
            echo O servico TermService esta desativado.
        ) else (
            echo O estado do servico TermService nao foi identificado corretamente.
        )
    )
)

echo.

echo Verificando o status do servico RemoteRegistry...

:: Verifica o status do serviço
sc query RemoteRegistry >nul 2>&1
if %errorlevel% neq 0 (
    echo O servico RemoteRegistry nao existe.
) else (
    :: Busca pela linha que contém o estado do serviço
    for /f "tokens=3" %%A in ('sc query RemoteRegistry ^| findstr /I /C:"STATE" /C:"ESTADO"') do (
        if "%%A"=="4" (
            echo O servico RemoteRegistry esta ativado.
        ) else if "%%A"=="1" (
            echo O servico RemoteRegistry esta desativado.
        ) else (
            echo O estado do servico RemoteRegistry nao foi identificado corretamente.
        )
    )
)

echo.

echo Verificando o status do servico WinRM...

:: Verifica o status do serviço
sc query WinRM >nul 2>&1
if %errorlevel% neq 0 (
    echo O servico WinRM nao existe.
) else (
    :: Busca pela linha que contém o estado do serviço
    for /f "tokens=3" %%A in ('sc query WinRM ^| findstr /I /C:"STATE" /C:"ESTADO"') do (
        if "%%A"=="4" (
            echo O servico WinRM esta ativado.
        ) else if "%%A"=="1" (
            echo O servico WinRM esta desativado.
        ) else (
            echo O estado do servico WinRM nao foi identificado corretamente.
        )
    )
)

echo .

echo Verificando os perfis de firewall...

rem Verificar o perfil de firewall Domain
for /f "tokens=*" %%A in ('powershell.exe -Command "(Get-NetFirewallProfile -Name Domain).Enabled"') do (
    set "DomainStatus=%%A"
)
if "%DomainStatus%"=="True" (
    echo O perfil de firewall Domain esta habilitado.
) else (
    echo O perfil de firewall Domain esta desabilitado ou nao existe.
)

rem Verificar o perfil de firewall Public
for /f "tokens=*" %%A in ('powershell.exe -Command "(Get-NetFirewallProfile -Name Public).Enabled"') do (
    set "PublicStatus=%%A"
)
if "%PublicStatus%"=="True" (
    echo O perfil de firewall Public esta habilitado.
) else (
    echo O perfil de firewall Public esta desabilitado ou nao existe.
)

rem Verificar o perfil de firewall Private
for /f "tokens=*" %%A in ('powershell.exe -Command "(Get-NetFirewallProfile -Name Private).Enabled"') do (
    set "PrivateStatus=%%A"
)
if "%PrivateStatus%"=="True" (
    echo O perfil de firewall Private esta habilitado.
) else (
    echo O perfil de firewall Private esta desabilitado ou nao existe.
)

echo .

echo Verificando o valor da chave de registro UseLogonCredential...

:: Consulta a chave de registro
reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential >nul 2>&1
if %errorlevel%==0 (
    rem Obtém o valor da chave de registro
    for /f "tokens=3" %%A in ('reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /s /v UseLogonCredential ^| findstr /i "UseLogonCredential"') do (
        if "%%A"=="0x0" (
            echo Tudo certo, a chave esta desativada.
        ) else (
            echo Cuidado! A chave esta ativada, o que pode expor senhas na memoria.
        )
    )
) else (
    echo A chave de registro UseLogonCredential nao existe ou esta com valor indefinido.
)

echo .

echo Verificando o status do servico WinHttpAutoProxySvc...

:: Verifica o status do serviço
sc query WinHttpAutoProxySvc >nul 2>&1
if %errorlevel%==0 (
    :: Busca pela linha que contém o estado do serviço
    for /f "tokens=3" %%A in ('sc query WinHttpAutoProxySvc ^| findstr /I /C:"STATE" /C:"ESTADO"') do (
        if "%%A"=="4" (
            echo O servico WinHttpAutoProxySvc esta ativado.
        ) else if "%%A"=="1" (
            echo O servico WinHttpAutoProxySvc esta desativado.
        ) else (
            echo O estado do servico WinHttpAutoProxySvc nao foi identificado corretamente.
        )
    )
) else (
    echo O servico WinHttpAutoProxySvc nao existe ou esta com valor indefinido.
)

echo .

rem SSL 2.0 Client
echo Verificando SSL 2.0 Client...
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v DisabledByDefault 2^>nul') do echo DisabledByDefault: %%A
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v Enabled 2^>nul') do echo Enabled: %%A
echo.

rem SSL 2.0 Server
echo Verificando SSL 2.0 Server...
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v DisabledByDefault 2^>nul') do echo DisabledByDefault: %%A
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v Enabled 2^>nul') do echo Enabled: %%A
echo.

rem SSL 3.0 Client
echo Verificando SSL 3.0 Client...
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v DisabledByDefault 2^>nul') do echo DisabledByDefault: %%A
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v Enabled 2^>nul') do echo Enabled: %%A
echo.

rem SSL 3.0 Server
echo Verificando SSL 3.0 Server...
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v DisabledByDefault 2^>nul') do echo DisabledByDefault: %%A
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v Enabled 2^>nul') do echo Enabled: %%A
echo.

rem TLS 1.0 Client
echo Verificando TLS 1.0 Client...
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault 2^>nul') do echo DisabledByDefault: %%A
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v Enabled 2^>nul') do echo Enabled: %%A
echo.

rem TLS 1.0 Server
echo Verificando TLS 1.0 Server...
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v DisabledByDefault 2^>nul') do echo DisabledByDefault: %%A
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v Enabled 2^>nul') do echo Enabled: %%A
echo.

rem TLS 1.1 Client
echo Verificando TLS 1.1 Client...
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v DisabledByDefault 2^>nul') do echo DisabledByDefault: %%A
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v Enabled 2^>nul') do echo Enabled: %%A
echo.

rem TLS 1.1 Server
echo Verificando TLS 1.1 Server...
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v DisabledByDefault 2^>nul') do echo DisabledByDefault: %%A
for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v Enabled 2^>nul') do echo Enabled: %%A
echo.

rem

echo .

echo Verificando o valor da chave de registro Enabled

rem Verifica se a chave de registro existe e consulta seu valor
for /f "tokens=3" %%A in ('reg query "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /s /v Enabled 2^>nul') do set chave=%%A

rem Verifica se o comando foi bem-sucedido e se a chave foi encontrada
if not defined chave (
    echo A chave de registro Enabled nao existe ou esta vazia.
) else (
    rem Verifica se o valor da chave é 0x0 (desativado)
    if /i "%chave%"=="0x0" (
        echo O Windows Script Host esta desativado.
    ) else if /i "%chave%"=="0x1" (
        rem Se for 0x1, significa que está ativado
        echo O Windows Script Host esta ativado.
    ) else (
        rem Caso o valor seja diferente de 0x0 ou 0x1, considera-se que o valor não é esperado
        echo O valor da chave Enabled e inesperado ou invalido: %chave%
    )
)

echo.

echo Verificando o status do protocolo SMB1...

rem Executar o comando PowerShell e armazenar o resultado
for /f "tokens=*" %%A in ('powershell -Command "(Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol)"') do set SMB1Status=%%A

rem Verificar o valor de EnableSMB1Protocol
if "%SMB1Status%"=="False" (
    echo O protocolo SMB1 esta desativado.
) else if "%SMB1Status%"=="True" (
    echo O protocolo SMB1 esta ativado.
) else (
    echo A chave de registro EnableSMB1Protocol nao existe ou esta com valor indefinido.
)

echo .

echo Verificando o valor da chave de registro RunAsPPL...

rem Verificar se a chave de registro existe
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL >nul 2>&1
if %errorlevel%==0 (
    rem Iterar sobre as possíveis chaves de registro
    for /f "tokens=3" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /s /v RunAsPPL 2^>nul') do (
        rem Verificar se o valor está ativado (0x1 ou 0x2)
        if "%%A"=="1" (
            echo A protecao LSA esta ativada.
        ) else if "%%A"=="2" (
            echo A protecao LSA esta ativada.
        ) else (
            echo A protecao LSA nao esta ativada. Valor encontrado: %%A
        )
    )
) else (
    echo A chave de registro RunAsPPL nao existe ou esta com valor indefinido.
)

echo .

echo Verificando o valor da chave de registro NetbiosOptions...

rem 
set GUID={NetbiosOptions}

rem 
set GUID={NetbiosOptions}

rem Listar todas as interfaces Tcpip_ para verificar se alguma tem NetBIOS desativado (valor 0x2)
for /f "tokens=*" %%G in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" /s /f Tcpip_ 2^>nul') do (
    rem Verificar se a chave atual contém o valor NetbiosOptions
    reg query "%%G" /v NetbiosOptions >nul 2>&1
    if %errorlevel%==0 (
        rem Ler o valor da chave NetbiosOptions
        for /f "tokens=3" %%A in ('reg query "%%G" /v NetbiosOptions 2^>nul') do (
            rem Verificar se o valor é 0x2
            if "%%A"=="0x2" (
                echo O NetBIOS esta desativado na interface: %%G
            ) else (
                echo O NetBIOS esta ativado na interface: %%G
            )
        )
    ) else (
        echo A chave NetbiosOptions nao existe para a interface: %%G
    )
)

echo .

echo Verificando o valor da chave de registro EnableMultiCast...

rem Executar o comando PowerShell e armazenar o resultado
for /f "tokens=*" %%A in ('powershell -Command "(Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol)"') do set SMB1Status=%%A

rem Verificar o valor de EnableSMB1Protocol
if "%SMB1Status%"=="False" (
    echo O protocolo SMB1 esta desativado.
) else if "%SMB1Status%"=="True" (
    echo O protocolo SMB1 esta ativado.
) else (
    echo A chave de registro EnableSMB1Protocol nao existe ou esta com valor indefinido.
)

echo .

echo Verificando as configuracoes de seguranca SMB...

:: Verificar a chave RequireSecuritySignature
for /f "tokens=*" %%A in ('powershell.exe -Command "Get-SmbServerConfiguration | Select RequireSecuritySignature | Format-Table -HideTableHeaders"') do (
    set "RequireSecuritySignature=%%A"
)

:: Remover espacos extras
set "RequireSecuritySignature=%RequireSecuritySignature: =%"

:: Verificar se a chave RequireSecuritySignature é válida
if "%RequireSecuritySignature%"=="True" (
    set "RequireSecuritySignatureStatus=ativado"
) else if "%RequireSecuritySignature%"=="False" (
    set "RequireSecuritySignatureStatus=desativado"
) else (
    set "RequireSecuritySignatureStatus=invalido ou nao existe"
)

:: Verificar a chave EncryptData
for /f "tokens=*" %%A in ('powershell.exe -Command "Get-SmbServerConfiguration | Select EncryptData | Format-Table -HideTableHeaders"') do (
    set "EncryptData=%%A"
)

:: Remover espacos extras
set "EncryptData=%EncryptData: =%"

:: Verificar se a chave EncryptData é válida
if "%EncryptData%"=="True" (
    set "EncryptDataStatus=ativado"
) else if "%EncryptData%"=="False" (
    set "EncryptDataStatus=desativado"
) else (
    set "EncryptDataStatus=invalido ou nao existe"
)

:: Verificar a chave EnableSecuritySignature
for /f "tokens=*" %%A in ('powershell.exe -Command "Get-SmbServerConfiguration | Select EnableSecuritySignature | Format-Table -HideTableHeaders"') do (
    set "EnableSecuritySignature=%%A"
)

:: Remover espacos extras
set "EnableSecuritySignature=%EnableSecuritySignature: =%"

:: Verificar se a chave EnableSecuritySignature é válida
if "%EnableSecuritySignature%"=="True" (
    set "EnableSecuritySignatureStatus=ativado"
) else if "%EnableSecuritySignature%"=="False" (
    set "EnableSecuritySignatureStatus=desativado"
) else (
    set "EnableSecuritySignatureStatus=invalido ou nao existe"
)

:: Exibir resultados
echo RequireSecuritySignature: %RequireSecuritySignatureStatus%
echo EncryptData: %EncryptDataStatus%
echo EnableSecuritySignature: %EnableSecuritySignatureStatus%

:: Verificar se todas as configurações estão ativadas
if "%RequireSecuritySignatureStatus%"=="ativado" if "%EncryptDataStatus%"=="ativado" if "%EnableSecuritySignatureStatus%"=="ativado" (
    echo As configuracoes de seguranca SMB estao ativadas.
) else (
    echo As configuracoes de seguranca SMB nao estao totalmente ativadas.
)

echo .

endlocal
pause
