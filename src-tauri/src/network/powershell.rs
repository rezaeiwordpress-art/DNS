
    
  
            .profile_name_server_reg
            .as_deref()
            .or(snapshot.static_name_server_reg.as_deref())
            .map(ToString::to_string)
            .unwrap_or_else(|| snapshot.server_addresses.join(","));

        self.run_fixed_script(
            "restore_ipv6_dns_emergency",
            RESTORE_IPV6_DNS_EMERGENCY_SCRIPT,
            &[
                ("DNS_CHANGER_ADAPTER_GUID", &canonical),
                ("DNS_CHANGER_IPV6_MODE", mode_str),
                ("DNS_CHANGER_IPV6_SERVERS", &servers_str),
            ],
            POWERSHELL_MUTATION_TIMEOUT_SECS,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_utf16le_base64_for_powershell_encoded_command() {
        let encoded = PowerShellNetworkBackend::encode_script("Write-Output 'ok'");
        assert!(!encoded.is_empty());
        let decoded = BASE64.decode(encoded).unwrap();
        assert_eq!(decoded.len() % 2, 0);
    }

    #[test]
    fn reset_script_is_strictly_ipv4_only_and_never_touches_ipv6_or_reset_server_addresses() {
        assert!(RESET_IPV4_DNS_SCRIPT.contains("netsh.exe interface ipv4 set dnsservers"));
        assert!(!RESET_IPV4_DNS_SCRIPT.contains("-ResetServerAddresses"));
        assert!(!RESET_IPV4_DNS_SCRIPT.contains("Tcpip6"));
        assert!(!RESET_IPV4_DNS_SCRIPT.contains("ipv6"));
    }

    #[test]
    fn set_script_validates_ipv4_inter_network_family_and_multi_server_csv() {
        assert!(SET_IPV4_DNS_SCRIPT.contains("AddressFamily]::InterNetwork"));
        assert!(SET_IPV4_DNS_SCRIPT.contains("DNS_CHANGER_DNS_SERVERS"));
        assert!(SET_IPV4_DNS_SCRIPT.contains("-gt 8"));
        assert!(!SET_IPV4_DNS_SCRIPT.contains("Tcpip6"));
        assert!(!SET_IPV4_DNS_SCRIPT.contains("-ResetServerAddresses"));
    }

    #[test]
    fn all_powershell_scripts_configure_utf8_output_encoding() {
        let expected = "try {\n    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n    $OutputEncoding = [System.Text.Encoding]::UTF8\n} catch { }";
        for script in [
            GET_ALL_ADAPTERS_SCRIPT,
            GET_ADAPTER_BY_GUID_SCRIPT,
            SET_IPV4_DNS_SCRIPT,
            RESET_IPV4_DNS_SCRIPT,
            GET_IPV6_DNS_STATE_SCRIPT,
            RESTORE_IPV6_DNS_EMERGENCY_SCRIPT,
        ] {
            assert!(
                script.contains(expected),
                "Expected PowerShell script to wrap UTF-8 output encoding setup in try/catch"
            );
        }
    }

    #[test]
    fn query_and_mutation_timeout_constants_differ_appropriately() {
        assert_eq!(POWERSHELL_QUERY_TIMEOUT_SECS, 45);
        assert_eq!(POWERSHELL_MUTATION_TIMEOUT_SECS, 15);
    }

    #[test]
    fn maps_blocked_antivirus_and_missing_cmdlet_stderr_to_powershell_blocked() {
        for msg in [
            "This script contains malicious content and has been blocked by your antivirus software.",
            "Program 'powershell.exe' failed to run: blocked by your antivirus.",
            "This script has been blocked by your organization's policy.",
            "File C:\\temp\\run.ps1 cannot be loaded because execution of scripts is disabled on this system.",
            "File C:\\temp\\run.ps1 cannot be loaded because running scripts is disabled on this system.",
            "The term 'Get-NetAdapter' is not recognized as the name of a cmdlet.",
            "The term 'Set-DnsClientServerAddress' is not recognized as the name of a cmdlet.",
            "netsh : The term 'netsh' is not recognized as the name of a cmdlet.",
        ] {
            let err = PowerShellNetworkBackend::map_powershell_failure(
                "get_all_adapters",
                1,
                msg,
                None,
            );
            assert!(
                matches!(err, AppError::PowershellBlocked { .. }),
                "Expected PowershellBlocked for stderr: {msg}"
            );
            assert!(err.to_string().contains("get_all_adapters"));
        }
    }

    #[test]
    fn maps_unrelated_is_not_recognized_error_to_execution_failed_with_stderr() {
        let msg = "The term 'Foo-Bar' is not recognized as the name of a cmdlet.";
        let err = PowerShellNetworkBackend::map_powershell_failure(
            "get_all_adapters",
            1,
            msg,
            None,
        );
        match err {
            AppError::PowershellExecutionFailed { detail } => {
                assert!(detail.contains("Foo-Bar"));
                assert!(detail.contains("is not recognized"));
            }
            other => panic!("Expected PowershellExecutionFailed, got {other:?}"),
        }
    }

    #[test]
    fn maps_access_denied_adapter_not_found_and_truncates_stderr_to_500_chars() {
        let long_stderr = "x".repeat(800);
        let fail_err = PowerShellNetworkBackend::map_powershell_failure(
            "get_all_adapters",
            1,
            &long_stderr,
            None,
        );
        match fail_err {
            AppError::PowershellExecutionFailed { detail } => {
                assert!(detail.contains(&"x".repeat(500)));
                assert!(!detail.contains(&"x".repeat(501)));
            }
            other => panic!("Expected PowershellExecutionFailed, got {other:?}"),
        }

        let timeout_err = PowerShellNetworkBackend::map_powershell_timeout(
            "get_adapter_by_guid",
            45,
            &long_stderr,
        );
        match timeout_err {
            AppError::PowershellTimeout {
                timeout_secs,
                detail,
            } => {
                assert_eq!(timeout_secs, 45);
                assert!(detail.contains(&"x".repeat(500)));
                assert!(!detail.contains(&"x".repeat(501)));
            }
            other => panic!("Expected PowershellTimeout, got {other:?}"),
        }

        let denied = PowerShellNetworkBackend::map_powershell_failure(
            "set_ipv4_dns",
            1,
            "Access is denied (0x80070005)",
            None,
        );
        assert!(matches!(denied, AppError::AdminAccessDenied { .. }));

        let missing = PowerShellNetworkBackend::map_powershell_failure(
            "set_ipv4_dns",
            1,
            "ADAPTER_NOT_FOUND:{11111111-2222-3333-4444-555555555555}",
            Some("{11111111-2222-3333-4444-555555555555}"),
        );
        assert!(matches!(missing, AppError::AdapterNotFound { .. }));
    }

    #[test]
    fn adapter_query_scripts_filter_loopback_tunnel_and_non_ipv4_in_dotnet_fallback() {
        for script in [GET_ALL_ADAPTERS_SCRIPT, GET_ADAPTER_BY_GUID_SCRIPT] {
            assert!(script.contains("GetAllNetworkInterfaces()"));
            assert!(script.contains("$niType -eq 'Loopback' -or $niType -eq 'Tunnel'"));
            assert!(script.contains("GetIPv4Properties()"));
            assert!(script.contains("if ($null -eq $ipv4Props)"));
            assert!(script.contains("[uint32]::TryParse"));
        }
    }

    #[test]
    fn dotnet_fallback_still_queries_tcpip_interface_signals() {
        let all_fallback = GET_ALL_ADAPTERS_SCRIPT
            .split("GetAllNetworkInterfaces()")
            .nth(1)
            .expect("Expected .NET fallback section in GET_ALL_ADAPTERS_SCRIPT");
        assert!(all_fallback.contains("Get-TcpipInterfaceSignals -Guid $guid"));

        let single_fallback = GET_ADAPTER_BY_GUID_SCRIPT
            .split("GetAllNetworkInterfaces()")
            .nth(1)
            .expect("Expected .NET fallback section in GET_ADAPTER_BY_GUID_SCRIPT");
        assert!(single_fallback.contains("Get-TcpipInterfaceSignals -Guid $guid"));

