<!DOCTYPE html>
<html lang="pt-br">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Página de Análise de Segurança</title>
    <link rel="stylesheet" href="analise.css">
</head>

<body>
    <div class="container">

        <h1>
            <?php
            // Comando para verificar o status do serviço TermService
            $commandTS = 'sc query TermService';

            // Executa o comando e captura a saída
            exec($commandTS, $outputTS, $return_varTS);

            // Verifica se o serviço está desativado
            $service_disabledTS = false;
            foreach ($outputTS as $lineTS) {
                if ((strpos($lineTS, 'STATE') !== false || strpos($lineTS, 'ESTADO') !== false) && strpos($lineTS, 'STOPPED') !== false) {
                    $service_disabledTS = true;
                    break;
                }
            }

            // Exibe o resultado
            if ($service_disabledTS) {
                echo "O serviço TermService está desativado.";
            } else {
                echo "O serviço TermService está ativado.";
            }
            //teste no sistemas->área de trabalho remota
            ?>
        </h1>

        <h1>
            <?php
            // Comando para verificar o status do serviço RemoteRegistry
            $commandRR = 'sc query RemoteRegistry';

            // Executa o comando e captura a saída
            exec($commandRR, $outputRR, $return_varRR);

            $service_disabledRR = false;
            foreach ($outputRR as $lineRR) {
                if ((strpos($lineRR, 'STATE') !== false || strpos($lineRR, 'ESTADO') !== false) && strpos($lineRR, 'STOPPED') !== false) {
                    $service_disabledRR = true;
                    break;
                }
            }

            // Exibe o resultado
            if ($service_disabledRR) {
                echo "O serviço RemoteRegistry está desativado.";
            } else {
                echo "O serviço RemoteRegistry está ativado.";
            }
            //teste no serviços->Registro remoto
            ?>
        </h1>

        <h1>
            <?php
            // Comando para verificar o status do serviço WinRM
            $commandWRM = 'sc query WinRM';

            // Executa o comando e captura a saída
            exec($commandWRM, $outputWRM, $return_varWRM);

            $service_disabledWRM = false;
            foreach ($outputWRM as $lineWRM) {
                if ((strpos($lineWRM, 'STATE') !== false || strpos($lineWRM, 'ESTADO') !== false) && strpos($lineWRM, 'STOPPED') !== false) {
                    $service_disabledWRM = true;
                    break;
                }
            }

            // Exibe o resultado
            if ($service_disabledWRM) {
                echo "O serviço WinRM está desativado.";
            } else {
                echo "O serviço WinRM está ativado.";
            }
            //teste no serviços->Windows Remote Management 
            ?>
        </h1>

        <h1>
            <?php
            // Comando para verificar o status dos perfis de firewall
            $commandWF = 'powershell.exe -Command "Get-NetFirewallProfile | Format-Table Name, Enabled"';

            // Executa o comando e captura a saída
            exec($commandWF, $outputWF, $return_varWF);

            $firewall_statusWF = [
                'Domain' => false,
                'Public' => false,
                'Private' => false
            ];

            // Verifica o status de cada perfil de firewall
            foreach ($outputWF as $lineWF) {
                if (strpos($lineWF, 'Domain') !== false && strpos($lineWF, 'True') !== false) {
                    $firewall_statusWF['Domain'] = true;
                }
                if (strpos($lineWF, 'Public') !== false && strpos($lineWF, 'True') !== false) {
                    $firewall_statusWF['Public'] = true;
                }
                if (strpos($lineWF, 'Private') !== false && strpos($lineWF, 'True') !== false) {
                    $firewall_statusWF['Private'] = true;
                }
            }

            // Exibe o resultado
            foreach ($firewall_statusWF as $profileWF => $enabledWF) {
                if ($enabledWF) {
                    echo "O perfil de firewall $profileWF está habilitado.<br>";
                } else {
                    echo "O perfil de firewall $profileWF está desabilitado.<br>";
                }
            }
            //teste->No CMD: netsh advfirewall set domainprofile state off e netsh advfirewall set domainprofile state on
            ?>
        </h1>

        <h1>
            <?php
            // Comando para verificar o valor da chave de registro UseLogonCredential
            $commandWD = 'reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential';

            // Executa o comando e captura a saída
            exec($commandWD, $outputWD, $return_varWD);

            // Verifica se a chave de registro existe e seu valor
            $key_existsWD = false;
            $cache_disabledWD = false;
            foreach ($outputWD as $lineWD) {
                if (strpos($lineWD, 'UseLogonCredential') !== false) {
                    $key_existsWD = true;
                    if (strpos($lineWD, '0x0') !== false) {
                        $cache_disabledWD = true;
                    }
                    break;
                }
            }

            // Exibe o resultado
            if ($key_existsWD) {
                if ($cache_disabledWD) {
                    echo "O cache de credenciais do WDigest está desativado.";
                } else {
                    echo "O cache de credenciais do WDigest está ativado (PERIGO).";
                }
            } else {
                echo "A chave de registro UseLogonCredential não existe ou está com valor indefinido.";
            }

            //teste->No CMD: reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 1 /f  e  reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
            ?>
        </h1>

        <h1>
            <?php
            // Comando para verificar o status do serviço WinHttpAutoProxySvc
            $commandWHAPS = 'sc query WinHttpAutoProxySvc';

            // Executa o comando e captura a saída
            exec($commandWHAPS, $outputWHAPS, $return_varWHAPS);

            $service_disabledWHAPS = false;
            foreach ($outputWHAPS as $lineWHAPS) {
                if ((strpos($lineWHAPS, 'STATE') !== false || strpos($lineWHAPS, 'ESTADO') !== false) && strpos($lineWHAPS, 'STOPPED') !== false) {
                    $service_disabledWHAPS = true;
                    break;
                }
            }

            // Exibe o resultado
            if ($service_disabledWHAPS) {
                echo "O serviço WinHttpAutoProxySvc está desativado.";
            } else {
                echo "O serviço WinHttpAutoProxySvc está ativado.";
            }
            //teste: para acessar-> Win+R, em seguida escreva: regedit, caminho: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc, busque a chave start->modificar  e mude o dado do valor de 3 para 4.
            ?>
        </h1>

        <h1>
            <?php
            // Comando para verificar o valor da chave de registro Enabled
            $commandCheckSH = 'reg query "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v Enabled';

            // Executa o comando e captura a saída
            exec($commandCheckSH, $outputCheckSH, $return_varCheckSH);

            $key_existsSH = false;
            $disabledSH = false;
            foreach ($outputCheckSH as $lineCheckSH) {
                if (strpos($lineCheckSH, 'Enabled') !== false) {
                    $key_existsSH = true;
                    if (strpos($lineCheckSH, '0x0') !== false) {
                        $disabledSH = true;
                    }
                    break;
                }
            }

            // Exibe o resultado
            if ($key_existsSH) {
                if ($disabledSH) {
                    echo "O Windows Script Host está desativado.";
                } else {
                    echo "O Windows Script Host está ativado.";
                }
            } else {
                echo "A chave de registro Enabled não existe ou está com valor indefinido.";
            }
            //teste: foi conferido no caminho: HKLM\SOFTWARE\Microsoft\Windows Script Host, porém a chave estava indefinida.
            ?>
        </h1>

    </div>

    <div class="container">

        <h1>
            <?php
            // Função para verificar o valor de uma chave de registro específica
            function checkProtocolStatus($protocolPathSSL_TLS, $valueNameSSL_TLS)
            {
                $commandSSL_TLS = 'reg query "' . $protocolPathSSL_TLS . '" /v ' . $valueNameSSL_TLS;
                exec($commandSSL_TLS, $outputSSL_TLS, $return_varSSL_TLS);

                if ($return_varSSL_TLS !== 0) {
                    return 'indefinida'; // A chave não existe
                }

                foreach ($outputSSL_TLS as $lineSSL_TLS) {
                    if (strpos($lineSSL_TLS, $valueNameSSL_TLS) !== false) {
                        $partsSSL_TLS = preg_split('/\s+/', trim($lineSSL_TLS));
                        return end($partsSSL_TLS); // Retorna o último valor (o valor da chave)
                    }
                }

                return 'indefinida';
            }

            // Caminhos e valores das chaves de registro para os protocolos
            $protocolsSSL_TLS = [
                'SSL 2.0 Client' => [
                    'path' => 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client',
                    'DisabledByDefault' => 'DisabledByDefault',
                    'Enabled' => 'Enabled'
                ],
                'SSL 2.0 Server' => [
                    'path' => 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server',
                    'DisabledByDefault' => 'DisabledByDefault',
                    'Enabled' => 'Enabled'
                ],
                'SSL 3.0 Client' => [
                    'path' => 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client',
                    'DisabledByDefault' => 'DisabledByDefault',
                    'Enabled' => 'Enabled'
                ],
                'SSL 3.0 Server' => [
                    'path' => 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server',
                    'DisabledByDefault' => 'DisabledByDefault',
                    'Enabled' => 'Enabled'
                ],
                'TLS 1.0 Client' => [
                    'path' => 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client',
                    'DisabledByDefault' => 'DisabledByDefault',
                    'Enabled' => 'Enabled'
                ],
                'TLS 1.0 Server' => [
                    'path' => 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server',
                    'DisabledByDefault' => 'DisabledByDefault',
                    'Enabled' => 'Enabled'
                ],
                'TLS 1.1 Client' => [
                    'path' => 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client',
                    'DisabledByDefault' => 'DisabledByDefault',
                    'Enabled' => 'Enabled'
                ],
                'TLS 1.1 Server' => [
                    'path' => 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server',
                    'DisabledByDefault' => 'DisabledByDefault',
                    'Enabled' => 'Enabled'
                ]
            ];

            // Verificação dos protocolos e exibição dos resultados
            foreach ($protocolsSSL_TLS as $protocolNameSSL_TLS => $protocolInfoSSL_TLS) {
                $disabledStatusSSL_TLS = checkProtocolStatus($protocolInfoSSL_TLS['path'], $protocolInfoSSL_TLS['DisabledByDefault']);
                $enabledStatusSSL_TLS = checkProtocolStatus($protocolInfoSSL_TLS['path'], $protocolInfoSSL_TLS['Enabled']);

                // Verifica se o protocolo está desativado corretamente
                if ($disabledStatusSSL_TLS === '0x1' && $enabledStatusSSL_TLS === '0x0') {
                    echo "$protocolNameSSL_TLS está desativado conforme exigido.<br>";
                } elseif ($disabledStatusSSL_TLS === '0x0' || $enabledStatusSSL_TLS === '0x1') {
                    echo "$protocolNameSSL_TLS está ativado, o que não atende ao requisito.<br>";
                } elseif ($disabledStatusSSL_TLS === 'indefinida' || $enabledStatusSSL_TLS === 'indefinida') {
                    echo "$protocolNameSSL_TLS está indefinida ou não existe.<br>";
                } else {
                    echo "$protocolNameSSL_TLS possui um valor desconhecido: DisabledByDefault=$disabledStatusSSL_TLS, Enabled=$enabledStatusSSL_TLS<br>";
                }
            }
            //teste: foi conferido por diversos caminhos, como: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client->porém as chaves estaram indefinidas.
            ?>
        </h1>

        <h1>
            <?php
            // Comando para verificar o valor da chave de registro EnableSMB1Protocol
            $commandCheckSMB = 'powershell.exe -Command "Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol"';

            // Executa o comando e captura a saída
            exec($commandCheckSMB, $outputCheckSMB, $return_varCheckSMB);

            $key_existsSMB = false;
            $disabledSMB = false;
            foreach ($outputCheckSMB as $lineCheckSMB) {
                if (strpos($lineCheckSMB, 'False') !== false) {
                    $key_existsSMB = true;
                    $disabledSMB = true;
                    break;
                } elseif (strpos($lineCheckSMB, 'True') !== false) {
                    $key_existsSMB = true;
                    break;
                }
            }

            // Exibe o resultado
            if ($key_existsSMB) {
                if ($disabledSMB) {
                    echo "O protocolo SMB1 está desativado.";
                } else {
                    echo "O protocolo SMB1 está ativado.";
                }
            } else {
                echo "A chave de registro EnableSMB1Protocol não existe ou está com valor indefinido.";
            }
            //teste: foi conferido com o comando: powershell.exe -Command "Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol".
            ?>
        </h1>

        <h1>
            <?php
            // Comando para verificar o valor da chave de registro RunAsPPL
            $commandCheckPPL = 'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL';

            // Executa o comando e captura a saída
            exec($commandCheckPPL, $outputCheckPPL, $return_varCheckPPL);

            $key_existsPPL = false;
            $disabledPPL = false;
            foreach ($outputCheckPPL as $lineCheckPPL) {
                if (strpos($lineCheckPPL, 'RunAsPPL') !== false) {
                    $key_existsPPL = true;
                    if (strpos($lineCheckPPL, '0x1') !== false || strpos($lineCheckPPL, '0x2') !== false) {
                        $disabledPPL = true;
                    }
                    break;
                }
            }

            // Exibe o resultado
            if ($key_existsPPL) {
                if ($disabledPPL) {
                    echo "A proteção LSA está ativada.";
                } else {
                    echo "A proteção LSA não está ativada.";
                }
            } else {
                echo "A chave de registro RunAsPPL não existe ou está com valor indefinido.";
            }
            //teste: foi conferido no CMD, por esse código: reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL, porém, não há essa chave.
            ?>
        </h1>

        <h1>
            <?php
            // Comando para verificar o valor da chave de registro NetbiosOptions
            $commandCheckNetbios = 'reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}" /v NetbiosOptions';

            // Executa o comando e captura a saída
            exec($commandCheckNetbios, $outputCheckNetbios, $return_varCheckNetbios);

            $key_existsNetbios = false;
            $disabledNetbios = false;
            foreach ($outputCheckNetbios as $lineCheckNetbios) {
                if (strpos($lineCheckNetbios, 'NetbiosOptions') !== false) {
                    $key_existsNetbios = true;
                    if (strpos($lineCheckNetbios, '0x2') !== false) {
                        $disabledNetbios = true;
                    }
                    break;
                }
            }

            // Exibe o resultado
            if ($key_existsNetbios) {
                if ($disabledNetbios) {
                    echo "O NetBIOS está desativado.";
                } else {
                    echo "O NetBIOS não está desativado.";
                }
            } else {
                echo "A chave de registro NetbiosOptions não existe ou está com valor indefinido.";
            }
            //teste: foi conferido no caminho: HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}, porém a chave estava indefinida.
            ?>
        </h1>

        <h1>
            <?php
            // Comando para verificar o valor da chave de registro EnableMultiCast
            $commandCheckMultiCast = 'reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMultiCast';

            // Executa o comando e captura a saída
            exec($commandCheckMultiCast, $outputCheckMultiCast, $return_varCheckMultiCast);

            $key_existsMultiCast = false;
            $disabledMultiCast = false;
            foreach ($outputCheckMultiCast as $lineCheckMultiCast) {
                if (strpos($lineCheckMultiCast, 'EnableMultiCast') !== false) {
                    $key_existsMultiCast = true;
                    if (strpos($lineCheckMultiCast, '0x0') !== false) {
                        $disabledMultiCast = true;
                    }
                    break;
                }
            }

            // Exibe o resultado
            if ($key_existsMultiCast) {
                if ($disabledMultiCast) {
                    echo "O LLMNR está desativado.";
                } else {
                    echo "O LLMNR não está desativado.";
                }
            } else {
                echo "A chave de registro EnableMultiCast não existe ou está com valor indefinido.";
            }
            //teste: foi conferido com o comando cmd: reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMultiCast, porém a chave estava indefinida.
            ?>
        </h1>

        <h1>
            <?php
            // Verificar RequireSecuritySignature
            $commandCheckRequireSecuritySignature = 'powershell.exe -Command "Get-SmbServerConfiguration | Select RequireSecuritySignature | Format-Table -HideTableHeaders"';
            exec($commandCheckRequireSecuritySignature, $outputCheckRequireSecuritySignature, $return_varCheckRequireSecuritySignature);
            $key_existsRequireSecuritySignature = false;
            $RequireSecuritySignatureStatus = "invalido ou nao existe";
            foreach ($outputCheckRequireSecuritySignature as $lineCheckRequireSecuritySignature) {
                if (strpos($lineCheckRequireSecuritySignature, 'True') !== false) {
                    $RequireSecuritySignatureStatus = "ativado";
                    $key_existsRequireSecuritySignature = true;
                    break;
                } elseif (strpos($lineCheckRequireSecuritySignature, 'False') !== false) {
                    $RequireSecuritySignatureStatus = "desativado";
                    $key_existsRequireSecuritySignature = true;
                    break;
                }
            }

            // Verificar EncryptData
            $commandCheckEncryptData = 'powershell.exe -Command "Get-SmbServerConfiguration | Select EncryptData | Format-Table -HideTableHeaders"';
            exec($commandCheckEncryptData, $outputCheckEncryptData, $return_varCheckEncryptData);
            $key_existsEncryptData = false;
            $EncryptDataStatus = "invalido ou nao existe";
            foreach ($outputCheckEncryptData as $lineCheckEncryptData) {
                if (strpos($lineCheckEncryptData, 'True') !== false) {
                    $EncryptDataStatus = "ativado";
                    $key_existsEncryptData = true;
                    break;
                } elseif (strpos($lineCheckEncryptData, 'False') !== false) {
                    $EncryptDataStatus = "desativado";
                    $key_existsEncryptData = true;
                    break;
                }
            }

            // Verificar EnableSecuritySignature
            $commandCheckEnableSecuritySignature = 'powershell.exe -Command "Get-SmbServerConfiguration | Select EnableSecuritySignature | Format-Table -HideTableHeaders"';
            exec($commandCheckEnableSecuritySignature, $outputCheckEnableSecuritySignature, $return_varCheckEnableSecuritySignature);
            $key_existsEnableSecuritySignature = false;
            $EnableSecuritySignatureStatus = "invalido ou nao existe";
            foreach ($outputCheckEnableSecuritySignature as $lineCheckEnableSecuritySignature) {
                if (strpos($lineCheckEnableSecuritySignature, 'True') !== false) {
                    $EnableSecuritySignatureStatus = "ativado";
                    $key_existsEnableSecuritySignature = true;
                    break;
                } elseif (strpos($lineCheckEnableSecuritySignature, 'False') !== false) {
                    $EnableSecuritySignatureStatus = "desativado";
                    $key_existsEnableSecuritySignature = true;
                    break;
                }
            }

            // Exibir resultados
            if ($key_existsRequireSecuritySignature) {
                echo "RequireSecuritySignature: $RequireSecuritySignatureStatus\n <br>";
            } else {
                echo "A chave de registro RequireSecuritySignature nao existe ou esta com valor indefinido.\n";
            }

            if ($key_existsEncryptData) {
                echo "EncryptData: $EncryptDataStatus\n <br>";
            } else {
                echo "A chave de registro EncryptData nao existe ou esta com valor indefinido.\n";
            }

            if ($key_existsEnableSecuritySignature) {
                echo "EnableSecuritySignature: $EnableSecuritySignatureStatus\n";
            } else {
                echo "A chave de registro EnableSecuritySignature nao existe ou esta com valor indefinido.\n";
            }

            // Verificar se todas as configurações estão ativadas
            if ($RequireSecuritySignatureStatus === "ativado" && $EncryptDataStatus === "ativado" && $EnableSecuritySignatureStatus === "ativado") {
                echo "<br>As configuracoes de seguranca SMB estao ativadas.\n <br>";
            } else {
                echo "<br>As configuracoes de seguranca SMB nao estao totalmente ativadas.\n";
            }

            //teste: foi feito a partir desse comando cmd: powershell.exe -Command "Get-SmbServerConfiguration | Select RequireSecuritySignature, EncryptData, EnableSecuritySignature | Format-Table -HideTableHeaders".
            ?>

        </h1>
    </div>

</body>

</html>