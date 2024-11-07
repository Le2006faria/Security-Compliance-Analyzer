@echo off
cls
setlocal

echo .

echo Verificando o status do servioo TermService...
sc query TermService >nul 2>&1
if %errorlevel% neq 0 (
    echo O servioo TermService nao existe.
) else (
    sc query TermService | findstr /I /C:"STATE" /C:"ESTADO" | findstr /I /C:"STOPPED" >nul
    if %errorlevel%==0 (
        echo O servioo TermService esta desativado.
    ) else (
        echo O servioo TermService esta ativado.
    )
)

echo.

echo Verificando o status do servioo RemoteRegistry...
sc query RemoteRegistry >nul 2>&1
if %errorlevel% neq 0 (
    echo O servioo RemoteRegistry nao existe.
) else (
    sc query RemoteRegistry | findstr /I /C:"STATE" /C:"ESTADO" | findstr /I /C:"STOPPED" >nul
    if %errorlevel%==0 (
        echo O servioo RemoteRegistry esta desativado.
    ) else (
        echo O servioo RemoteRegistry esta ativado.
    )
)

echo.

echo Verificando o status do servioo WinRM...
sc query WinRM >nul 2>&1
if %errorlevel% neq 0 (
    echo O servioo WinRM nao existe.
) else (
    sc query WinRM | findstr /I /C:"STATE" /C:"ESTADO" | findstr /I /C:"STOPPED" >nul
    if %errorlevel%==0 (
        echo O servioo WinRM esta desativado.
    ) else (
        echo O servioo WinRM esta ativado.
    )
)

echo .

echo Verificando os perfis de firewall...

rem Verificar o perfil de firewall Domain
powershell.exe -Command "if (Get-NetFirewallProfile -Name Domain) { Get-NetFirewallProfile -Name Domain | Format-Table Name, Enabled } else { exit 1 }" | findstr /I /C:"Domain" /C:"True" >nul
if %errorlevel%==0 (
    echo O perfil de firewall Domain esta habilitado.
) else (
    if %errorlevel%==1 (
        echo O perfil de firewall Domain nao existe.
    ) else (
        echo O perfil de firewall Domain esta desabilitado.
    )
)

rem Verificar o perfil de firewall Public
powershell.exe -Command "if (Get-NetFirewallProfile -Name Public) { Get-NetFirewallProfile -Name Public | Format-Table Name, Enabled } else { exit 1 }" | findstr /I /C:"Public" /C:"True" >nul
if %errorlevel%==0 (
    echo O perfil de firewall Public esta habilitado.
) else (
    if %errorlevel%==1 (
        echo O perfil de firewall Public nao existe.
    ) else (
        echo O perfil de firewall Public esta desabilitado.
    )
)

rem Verificar o perfil de firewall Private
powershell.exe -Command "if (Get-NetFirewallProfile -Name Private) { Get-NetFirewallProfile -Name Private | Format-Table Name, Enabled } else { exit 1 }" | findstr /I /C:"Private" /C:"True" >nul
if %errorlevel%==0 (
    echo O perfil de firewall Private esta habilitado.
) else (
    if %errorlevel%==1 (
        echo O perfil de firewall Private nao existe.
    ) else (
        echo O perfil de firewall Private esta desabilitado.
    )
)


echo .

echo Verificando o valor da chave de registro UseLogonCredential...
reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential >nul 2>&1
if %errorlevel%==0 (
    for /f "tokens=3" %%A in ('reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential 2^>nul') do (
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
sc query WinHttpAutoProxySvc >nul 2>&1
if %errorlevel%==0 (
    sc query WinHttpAutoProxySvc | findstr /I /C:"STATE" /C:"ESTADO" | findstr /I /C:"STOPPED" >nul
    if %errorlevel%==0 (
        echo O servico WinHttpAutoProxySvc esta desativado.
    ) else (
        echo O servico WinHttpAutoProxySvc esta ativado.
    )
) else (
    echo O servico WinHttpAutoProxySvc nao existe ou esta com valor indefinido.
)

echo .

@echo off

rem Verificar o status das chaves de registro para SSL 2.0
if exist "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" (
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v DisabledByDefault 2^>nul') do set "SSL2ClientDisabled=%%A"
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v Enabled 2^>nul') do set "SSL2ClientEnabled=%%A"
) else (
    set "SSL2ClientDisabled=nao existe ou esta com valor indefinida"
    set "SSL2ClientEnabled=nao existe ou esta com valor indefinida"
)

if exist "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" (
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v DisabledByDefault 2^>nul') do set "SSL2ServerDisabled=%%A"
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v Enabled 2^>nul') do set "SSL2ServerEnabled=%%A"
) else (
    set "SSL2ServerDisabled=nao existe ou esta com valor indefinida"
    set "SSL2ServerEnabled=nao existe ou esta com valor indefinida"
)

rem Verificar o status das chaves de registro para SSL 3.0
if exist "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" (
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v DisabledByDefault 2^>nul') do set "SSL3ClientDisabled=%%A"
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v Enabled 2^>nul') do set "SSL3ClientEnabled=%%A"
) else (
    set "SSL3ClientDisabled=nao existe ou esta com valor indefinida"
    set "SSL3ClientEnabled=nao existe ou esta com valor indefinida"
)

if exist "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" (
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v DisabledByDefault 2^>nul') do set "SSL3ServerDisabled=%%A"
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v Enabled 2^>nul') do set "SSL3ServerEnabled=%%A"
) else (
    set "SSL3ServerDisabled=nao existe ou esta com valor indefinida"
    set "SSL3ServerEnabled=nao existe ou esta com valor indefinida"
)

rem Verificar o status das chaves de registro para TLS 1.0
if exist "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" (
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault 2^>nul') do set "TLS10ClientDisabled=%%A"
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v Enabled 2^>nul') do set "TLS10ClientEnabled=%%A"
) else (
    set "TLS10ClientDisabled=nao existe ou esta com valor indefinida"
    set "TLS10ClientEnabled=nao existe ou esta com valor indefinida"
)

if exist "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" (
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v DisabledByDefault 2^>nul') do set "TLS10ServerDisabled=%%A"
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v Enabled 2^>nul') do set "TLS10ServerEnabled=%%A"
) else (
    set "TLS10ServerDisabled=nao existe ou esta com valor indefinida"
    set "TLS10ServerEnabled=nao existe ou esta com valor indefinida"
)

rem Verificar o status das chaves de registro para TLS 1.1
if exist "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" (
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v DisabledByDefault 2^>nul') do set "TLS11ClientDisabled=%%A"
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v Enabled 2^>nul') do set "TLS11ClientEnabled=%%A"
) else (
    set "TLS11ClientDisabled=nao existe ou esta com valor indefinida"
    set "TLS11ClientEnabled=nao existe ou esta com valor indefinida"
)

if exist "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" (
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v DisabledByDefault 2^>nul') do set "TLS11ServerDisabled=%%A"
    for /f "tokens=3" %%A in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v Enabled 2^>nul') do set "TLS11ServerEnabled=%%A"
) else (
    set "TLS11ServerDisabled=nao existe ou esta com valor indefinida"
    set "TLS11ServerEnabled=nao existe ou esta com valor indefinida"
)

rem Verificar se os valores estao de acordo com as exigências
echo Verificando os valores exigidos...

echo SSL 2.0 Client:
echo DisabledByDefault: %SSL2ClientDisabled% (exigido: 1)
echo Enabled: %SSL2ClientEnabled% (exigido: 0)

echo SSL 2.0 Server:
echo DisabledByDefault: %SSL2ServerDisabled% (exigido: 1)
echo Enabled: %SSL2ServerEnabled% (exigido: 0)

echo SSL 3.0 Client:
echo DisabledByDefault: %SSL3ClientDisabled% (exigido: 1)
echo Enabled: %SSL3ClientEnabled% (exigido: 0)

echo SSL 3.0 Server:
echo DisabledByDefault: %SSL3ServerDisabled% (exigido: 1)
echo Enabled: %SSL3ServerEnabled% (exigido: 0)

echo TLS 1.0 Client:
echo DisabledByDefault: %TLS10ClientDisabled% (exigido: 1)
echo Enabled: %TLS10ClientEnabled% (exigido: 0)

echo TLS 1.0 Server:
echo DisabledByDefault: %TLS10ServerDisabled% (exigido: 1)
echo Enabled: %TLS10ServerEnabled% (exigido: 0)

echo TLS 1.1 Client:
echo DisabledByDefault: %TLS11ClientDisabled% (exigido: 1)
echo Enabled: %TLS11ClientEnabled% (exigido: 0)

echo TLS 1.1 Server:
echo DisabledByDefault: %TLS11ServerDisabled% (exigido: 1)
echo Enabled: %TLS11ServerEnabled% (exigido: 0)

echo .

echo Verificando o status do Windows Script Host...
reg query "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled >nul 2>&1
if %errorlevel%==0 (
    for /f "tokens=3" %%A in ('reg query "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled 2^>nul') do (
        if "%%A"=="0x0" (
            echo O Windows Script Host esta desativado.
        ) else (
            echo O Windows Script Host esta ativado.
        )
    )
) else (
    echo A chave de registro Script Host nao existe ou esta com valor indefinido.
)

echo .

echo Verificando o status do protocolo SMB1...
powershell.exe -Command "Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol" | findstr /I /C:"False" >nul
if %errorlevel%==0 (
    echo O protocolo SMB1 esta desativado.
) else (
    powershell.exe -Command "Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol" | findstr /I /C:"True" >nul
    if %errorlevel%==0 (
        echo O protocolo SMB1 esta ativado.
    ) else (
        echo A chave de registro EnableSMB1Protocol nao existe ou esta com valor indefinido.
    )
)

echo .

echo Verificando o valor da chave de registro RunAsPPL...
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL >nul 2>&1
if %errorlevel%==0 (
    for /f "tokens=3" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL 2^>nul') do (
        if "%%A"=="0x1" (
            echo A protecao LSA esta ativada.
        ) else if "%%A"=="0x2" (
            echo A protecao LSA esta ativada.
        ) else (
            echo A protecao LSA nao esta ativada.
        )
    )
) else (
    echo A chave de registro RunAsPPL nao existe ou esta com valor indefinido.
)

echo .

echo Verificando o valor da chave de registro NetbiosOptions...
reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}" /v NetbiosOptions >nul 2>&1
if %errorlevel%==0 (
    for /f "tokens=3" %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}" /v NetbiosOptions 2^>nul') do (
        if "%%A"=="0x2" (
            echo O NetBIOS esta desativado.
        ) else (
            echo O NetBIOS nao esta desativado.
        )
    )
) else (
    echo A chave de registro NetbiosOptions nao existe ou esta com valor indefinido.
)

echo .

echo Verificando o valor da chave de registro EnableMultiCast...
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMultiCast >nul 2>&1
if %errorlevel%==0 (
    for /f "tokens=3" %%A in ('reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMultiCast 2^>nul') do (
        if "%%A"=="0x0" (
            echo O LLMNR esta desativado.
        ) else (
            echo O LLMNR nao esta desativado.
        )
    )
) else (
    echo A chave de registro EnableMultiCast nao existe ou esta com valor indefinido.
)

echo .

echo Verificando as configuracoes de seguranca SMB...

:: Verificar a chave RequireSecuritySignature
for /f "tokens=*" %%A in ('powershell.exe -Command "Get-SmbServerConfiguration | Select RequireSecuritySignature | Format-Table -HideTableHeaders"') do (
    set "RequireSecuritySignature=%%A"
)

:: Remover espacos extras
set "RequireSecuritySignature=%RequireSecuritySignature: =%"

:: Verificar se a chave RequireSecuritySignature é valida
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

:: Verificar se a chave EncryptData é valida
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

:: Verificar se a chave EnableSecuritySignature é valida
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

:: Verificar se todas as configuracões estao ativadas
if "%RequireSecuritySignatureStatus%"=="ativado" if "%EncryptDataStatus%"=="ativado" if "%EnableSecuritySignatureStatus%"=="ativado" (
    echo As configuracoes de seguranca SMB estao ativadas.
) else (
    echo As configuracoes de seguranca SMB nao estao totalmente ativadas.
)

echo .

endlocal
pause
