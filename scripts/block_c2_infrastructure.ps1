# Define Malicious C2 Target
$C2_IP = "45.131.214.85"

$RuleName = "SOC-IR-BLOCK-C2-NetSupport-$C2_IP"

Write-Host "[*] Starting Incident Response Containment Action..." -ForegroundColor Yellow

# Check if rule already exists
$ExistingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue

if ($ExistingRule) {
    Write-Host "[!] Firewall rule for $C2_IP already exists. Containment active." -ForegroundColor Green
} else {
    Write-Host "[+] Creating Outbound & Inbound Block Rules for C2 IP: $C2_IP" -ForegroundColor Red
    
    # Block Outbound Traffic (Stops victim from sending beaconing packets)
    New-NetFirewallRule -DisplayName "$RuleName-Outbound" `
                        -Direction Outbound `
                        -RemoteAddress $C2_IP `
                        -Action Block `
                        -Protocol Any `
                        -Enabled True `
                        -Description "Automated SOC Block: NetSupport RAT C2 Beaconing"

    # Block Inbound Traffic (Stops C2 from sending remote commands)
    New-NetFirewallRule -DisplayName "$RuleName-Inbound" `
                        -Direction Inbound `
                        -RemoteAddress $C2_IP `
                        -Action Block `
                        -Protocol Any `
                        -Enabled True `
                        -Description "Automated SOC Block: NetSupport RAT C2 Beaconing"

    Write-Host "[SUCCESS] Host firewall rules applied successfully! Traffic to $C2_IP is fully isolated." -ForegroundColor Green
}