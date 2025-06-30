# M365 Proofpoint IP Transport Rule Manager
# PowerShell GUI Application for managing Exchange Online transport rules



# Load required assemblies
try {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
}
catch {
    Write-Host "ERROR: Failed to load Windows Forms assemblies. .NET Framework may be missing." -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Global variables
$global:isAuthenticated = $false
$global:ruleExists = $false
$global:outputText = ""
$global:mainForm = $null



# Proofpoint IP ranges
$ProofpointIPs = @(
    '67.231.149.0/24', '67.231.152.0/24', '67.231.153.0/24', '67.231.154.0/24', 
    '67.231.155.0/24', '67.231.156.0/24', '67.231.144.0/24', '67.231.145.0/24', 
    '67.231.146.0/24', '67.231.147.0/24', '67.231.148.0/24', '148.163.128.0/24', 
    '148.163.129.0/24', '148.163.130.0/24', '148.163.131.0/24', '148.163.132.0/24', 
    '148.163.133.0/24', '148.163.134.0/24', '148.163.135.0/24', '148.163.136.0/24', 
    '148.163.137.0/24', '148.163.138.0/24', '148.163.139.0/24', '148.163.140.0/24', 
    '148.163.141.0/24', '148.163.142.0/24', '148.163.143.0/24', '148.163.144.0/24', 
    '148.163.145.0/24', '148.163.146.0/24', '148.163.147.0/24', '148.163.148.0/24', 
    '148.163.149.0/24', '148.163.150.0/24', '148.163.151.0/24', '148.163.152.0/24', 
    '148.163.153.0/24', '148.163.154.0/24', '148.163.155.0/24', '148.163.156.0/24', 
    '148.163.157.0/24', '148.163.158.0/24', '148.163.159.0/24'
)

# Function to get or create the main form
function Get-MainForm {
    if ($global:mainForm -eq $null) {
        Write-Host "Creating main application form..." -ForegroundColor Green
        $global:mainForm = New-Object System.Windows.Forms.Form
        $global:mainForm.Text = "M365 Proofpoint IP Transport Rule Manager"
        $global:mainForm.Size = New-Object System.Drawing.Size(600, 400)
        $global:mainForm.StartPosition = "CenterScreen"
        $global:mainForm.FormBorderStyle = "FixedDialog"
        $global:mainForm.MaximizeBox = $false
        $global:mainForm.BackColor = [System.Drawing.Color]::White
        
        # Add form closing event to clean up
        $global:mainForm.Add_FormClosing({
            Write-Host "Application closing..." -ForegroundColor Yellow
        })
    }
    return $global:mainForm
}

# Function to clear form controls
function Clear-FormControls {
    param($form)
    Write-Host "Clearing form controls..." -ForegroundColor Gray
    $form.Controls.Clear()
}

# Screen 1: Authentication Screen
function Show-Screen1 {
    Write-Host "=== Loading Screen 1: Authentication ===" -ForegroundColor Cyan
    $form = Get-MainForm
    Clear-FormControls -form $form
    $form.Text = "M365 Proofpoint IP Transport Rule Manager - Authentication"
    
    # Title label
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = "Limit Email Reception to Proofpoint IPs"
    $titleLabel.Font = New-Object System.Drawing.Font("Arial", 16, [System.Drawing.FontStyle]::Bold)
    $titleLabel.Size = New-Object System.Drawing.Size(550, 50)
    $titleLabel.Location = New-Object System.Drawing.Point(25, 30)
    $titleLabel.TextAlign = "MiddleCenter"
    $titleLabel.ForeColor = [System.Drawing.Color]::DarkBlue
    $form.Controls.Add($titleLabel)
    
    # Description label
    $descLabel = New-Object System.Windows.Forms.Label
    $descLabel.Text = "This tool will setup a transport rule to limit Exchange Online email reception to Proofpoint IPs only. Please be patient, if the application looks like it's frozen, it's not. It's just working."
    $descLabel.Font = New-Object System.Drawing.Font("Arial", 10)
    $descLabel.Size = New-Object System.Drawing.Size(500, 60)
    $descLabel.Location = New-Object System.Drawing.Point(50, 100)
    $descLabel.TextAlign = "MiddleCenter"
    $form.Controls.Add($descLabel)
    
    # Authentication button
    $authButton = New-Object System.Windows.Forms.Button
    $authButton.Text = "Authenticate with Microsoft 365"
    $authButton.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
    $authButton.Size = New-Object System.Drawing.Size(300, 50)
    $authButton.Location = New-Object System.Drawing.Point(150, 200)
    $authButton.BackColor = [System.Drawing.Color]::LightBlue
    $authButton.FlatStyle = "Flat"
    $authButton.Add_Click({
        try {
            Write-Host "Authentication button clicked" -ForegroundColor Green
            
            # Safely update UI elements
            try {
                if ($authButton -ne $null) {
                    $authButton.Text = "Working..."
                    $authButton.Enabled = $false
                }
                if ($statusLabel -ne $null) {
                    $statusLabel.Text = "Starting authentication process..."
                }
            }
            catch {
                Write-Host "Error updating UI: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            Write-Host "=== Authentication Process Started ===" -ForegroundColor Cyan
            
            # Check for Exchange Online module
            Write-Host "Checking for ExchangeOnlineManagement module..." -ForegroundColor Green
            try {
                if ($statusLabel -ne $null) {
                    $statusLabel.Text = "Checking modules..."
                }
                if ($form -ne $null) {
                    $form.Refresh()
                }
            }
            catch {
                Write-Host "Error updating UI during module check: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            $moduleInstalled = Get-Module -ListAvailable -Name ExchangeOnlineManagement -ErrorAction SilentlyContinue
            
            if (-not $moduleInstalled) {
                Write-Host "ExchangeOnlineManagement module not found" -ForegroundColor Yellow
                $result = [System.Windows.Forms.MessageBox]::Show("The ExchangeOnlineManagement module is required but not installed.`n`nWould you like to install it now?`n`n(This may take a few minutes)", "Install Required Module", "YesNo", "Question")
                
                if ($result -eq "No") {
                    throw "Cannot proceed without ExchangeOnlineManagement module"
                }
                
                Write-Host "Installing ExchangeOnlineManagement module..." -ForegroundColor Green
                try {
                    if ($statusLabel -ne $null) {
                        $statusLabel.Text = "Installing ExchangeOnlineManagement module..."
                    }
                    if ($form -ne $null) {
                        $form.Refresh()
                    }
                }
                catch {
                    Write-Host "Error updating UI during module install: $($_.Exception.Message)" -ForegroundColor Red
                }
                
                # Install module
                Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser -SkipPublisherCheck
                Write-Host "Module installed successfully" -ForegroundColor Green
            }
            
            # Import the module
            Write-Host "Loading ExchangeOnlineManagement module..." -ForegroundColor Green
            try {
                if ($statusLabel -ne $null) {
                    $statusLabel.Text = "Loading module..."
                }
                if ($form -ne $null) {
                    $form.Refresh()
                }
            }
            catch {
                Write-Host "Error updating UI during module load: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            Import-Module ExchangeOnlineManagement -Force
            
            # Connect to Exchange Online
            Write-Host "Connecting to Exchange Online..." -ForegroundColor Green
            try {
                if ($authButton -ne $null) {
                    $authButton.Text = "Authenticating..."
                }
                if ($statusLabel -ne $null) {
                    $statusLabel.Text = "Connecting to Exchange Online..."
                }
                if ($form -ne $null) {
                    $form.Refresh()
                }
            }
            catch {
                Write-Host "Error updating UI during connection: $($_.Exception.Message)" -ForegroundColor Red
            }
            
            Connect-ExchangeOnline -ShowProgress:$false -WarningAction SilentlyContinue
            $global:isAuthenticated = $true
            
            Write-Host "Successfully authenticated!" -ForegroundColor Green
            Show-Screen2
        }
        catch {
            $errorMessage = $_.Exception.Message
            Write-Host "=== Authentication Error ===" -ForegroundColor Red
            Write-Host "Error: $errorMessage" -ForegroundColor Red
            Write-Host "Stack Trace: $($_.Exception.StackTrace)" -ForegroundColor Red
            
            # Simple error handling
            if ($errorMessage -like "*declined*") {
                [System.Windows.Forms.MessageBox]::Show("Cannot proceed without the ExchangeOnlineManagement module.", "Module Required", "OK", "Warning")
            } else {
                [System.Windows.Forms.MessageBox]::Show("Authentication failed: $errorMessage`n`nTry:`n1. Running as Administrator`n2. Installing the module manually: Install-Module -Name ExchangeOnlineManagement", "Authentication Error", "OK", "Error")
            }
            
            # Safely reset UI
            try {
                if ($authButton -ne $null) {
                    $authButton.Text = "Authenticate with Microsoft 365"
                    $authButton.Enabled = $true
                }
                if ($statusLabel -ne $null) {
                    $statusLabel.Text = "Please authenticate to continue..."
                }
            }
            catch {
                Write-Host "Error resetting UI: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    })
    $form.Controls.Add($authButton)
    
    # Status label
    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Text = "Please authenticate to continue..."
    $statusLabel.Font = New-Object System.Drawing.Font("Arial", 9)
    $statusLabel.Size = New-Object System.Drawing.Size(400, 20)
    $statusLabel.Location = New-Object System.Drawing.Point(100, 280)
    $statusLabel.TextAlign = "MiddleCenter"
    $statusLabel.ForeColor = [System.Drawing.Color]::Gray
    $form.Controls.Add($statusLabel)
    
    Write-Host "Screen 1 loaded successfully" -ForegroundColor Green
}

# Screen 2: Rule Check and Creation Screen
function Show-Screen2 {
    try {
        Write-Host "=== Loading Screen 2: Rule Status ===" -ForegroundColor Cyan
        $form = Get-MainForm
        Clear-FormControls -form $form
        $form.Text = "M365 Proofpoint IP Transport Rule Manager - Rule Status"
        Write-Host "Form prepared for Screen 2" -ForegroundColor Green
    
        # Title label
        Write-Host "Creating title label..." -ForegroundColor Green
        $titleLabel = New-Object System.Windows.Forms.Label
        $titleLabel.Text = "Transport Rule Status"
        $titleLabel.Font = New-Object System.Drawing.Font("Arial", 16, [System.Drawing.FontStyle]::Bold)
        $titleLabel.Size = New-Object System.Drawing.Size(550, 30)
        $titleLabel.Location = New-Object System.Drawing.Point(25, 20)
        $titleLabel.TextAlign = "MiddleCenter"
        $titleLabel.ForeColor = [System.Drawing.Color]::DarkBlue
        $form.Controls.Add($titleLabel)
        Write-Host "Title label created successfully" -ForegroundColor Green
    
        # Rule name label
        Write-Host "Creating rule name label..." -ForegroundColor Green
        $ruleLabel = New-Object System.Windows.Forms.Label
        $ruleLabel.Text = "Transport Rule: Block Messages from Unauthorized IPs"
        $ruleLabel.Font = New-Object System.Drawing.Font("Arial", 12)
        $ruleLabel.Size = New-Object System.Drawing.Size(500, 25)
        $ruleLabel.Location = New-Object System.Drawing.Point(50, 80)
        $ruleLabel.TextAlign = "MiddleCenter"
        $form.Controls.Add($ruleLabel)
        Write-Host "Rule name label created successfully" -ForegroundColor Green
    
        # Status indicator (circle)
        Write-Host "Creating status panel..." -ForegroundColor Green
        $statusPanel = New-Object System.Windows.Forms.Panel
        Write-Host "Status panel object created" -ForegroundColor Green
        
        $statusPanel.Size = New-Object System.Drawing.Size(60, 60)
        $statusPanel.Location = New-Object System.Drawing.Point(270, 120)
        $statusPanel.BackColor = [System.Drawing.Color]::Red
        Write-Host "Status panel properties set" -ForegroundColor Green
        
        # Skip the paint event for now to test
        # $statusPanel.Paint.Add({
        #     param($sender, $e)
        #     try {
        #         if ($sender -ne $null -and $e -ne $null -and $e.Graphics -ne $null) {
        #             $brush = New-Object System.Drawing.SolidBrush($sender.BackColor)
        #             $e.Graphics.FillEllipse($brush, 5, 5, 50, 50)
        #             $brush.Dispose()
        #         }
        #     }
        #     catch {
        #         Write-Host "Error in paint event: $($_.Exception.Message)" -ForegroundColor Yellow
        #     }
        # })
        Write-Host "About to add status panel to form..." -ForegroundColor Green
        $form.Controls.Add($statusPanel)
        Write-Host "Status panel added successfully" -ForegroundColor Green
    
        # Status text
        Write-Host "Creating status text label..." -ForegroundColor Green
        $statusText = New-Object System.Windows.Forms.Label
        $statusText.Text = "Checking rule status..."
        $statusText.Font = New-Object System.Drawing.Font("Arial", 10)
        $statusText.Size = New-Object System.Drawing.Size(300, 20)
        $statusText.Location = New-Object System.Drawing.Point(150, 190)
        $statusText.TextAlign = "MiddleCenter"
        $form.Controls.Add($statusText)
        Write-Host "Status text label created successfully" -ForegroundColor Green
    
        # Add Rule button
        Write-Host "Creating add rule button..." -ForegroundColor Green
        $addRuleButton = New-Object System.Windows.Forms.Button
        $addRuleButton.Text = "Add Transport Rule"
        $addRuleButton.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
        $addRuleButton.Size = New-Object System.Drawing.Size(200, 40)
        $addRuleButton.Location = New-Object System.Drawing.Point(200, 230)
        $addRuleButton.BackColor = [System.Drawing.Color]::LightGreen
        $addRuleButton.FlatStyle = "Flat"
        $addRuleButton.Enabled = $false
        Write-Host "Add rule button properties set" -ForegroundColor Green
        
        $addRuleButton.Add_Click({
            Show-Screen3
        })
        Write-Host "Add rule button click event added" -ForegroundColor Green
        
        $form.Controls.Add($addRuleButton)
        Write-Host "Add rule button added successfully" -ForegroundColor Green
    
        # Back button
        Write-Host "Creating back button..." -ForegroundColor Green
        $backButton = New-Object System.Windows.Forms.Button
        $backButton.Text = "Back"
        $backButton.Size = New-Object System.Drawing.Size(80, 30)
        $backButton.Location = New-Object System.Drawing.Point(50, 320)
        $backButton.Add_Click({
            Show-Screen1
        })
        $form.Controls.Add($backButton)
        Write-Host "Back button created successfully" -ForegroundColor Green
    
        Write-Host "All UI elements created successfully" -ForegroundColor Green
        
        # Check for existing transport rule
        Write-Host "Starting transport rule check..." -ForegroundColor Green
        try {
            Write-Host "=== Screen 2: Checking Transport Rule ===" -ForegroundColor Cyan
        
        $statusText.Text = "Checking for existing rule..."
        $form.Refresh()
        
        # Simple connection test
        Write-Host "Testing Exchange Online connection..." -ForegroundColor Green
        try {
            # Try a simple command to test connection
            $testConnection = Get-OrganizationConfig -ErrorAction Stop
            Write-Host "Connection test successful" -ForegroundColor Green
        }
        catch {
            Write-Host "Connection test failed: $($_.Exception.Message)" -ForegroundColor Red
            throw "Exchange Online connection lost. Please restart the application and authenticate again."
        }
        
        # Check for the transport rule
        Write-Host "Checking for transport rule: Block Messages from Unauthorized IPs" -ForegroundColor Green
        $existingRule = $null
        $ruleFound = $false
        
        try {
            $existingRule = Get-TransportRule -Identity "Block Messages from Unauthorized IPs" -ErrorAction Stop
            if ($existingRule) {
                $ruleFound = $true
                Write-Host "Transport rule found" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "Transport rule not found or error: $($_.Exception.Message)" -ForegroundColor Yellow
            $ruleFound = $false
        }
        
        # Update UI based on results
        if ($ruleFound) {
            $global:ruleExists = $true
            $statusPanel.BackColor = [System.Drawing.Color]::Green
            $statusText.Text = "Rule exists - No action needed"
            $statusText.ForeColor = [System.Drawing.Color]::Green
            $addRuleButton.Text = "Rule Already Exists"
            $addRuleButton.BackColor = [System.Drawing.Color]::LightGray
            $addRuleButton.Enabled = $false
            Write-Host "UI updated: Rule exists" -ForegroundColor Green
        } else {
            $global:ruleExists = $false
            $statusPanel.BackColor = [System.Drawing.Color]::Red
            $statusText.Text = "Rule not found - Click to add"
            $statusText.ForeColor = [System.Drawing.Color]::Red
            $addRuleButton.Enabled = $true
            Write-Host "UI updated: Rule not found" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Error in rule checking: $($_.Exception.Message)" -ForegroundColor Red
        $statusText.Text = "Error checking rule status: $($_.Exception.Message)"
        $statusText.ForeColor = [System.Drawing.Color]::Orange
        $addRuleButton.Enabled = $false
    }
    
        Write-Host "Screen 2 loaded successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "=== Screen 2 Error ===" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Stack Trace: $($_.Exception.StackTrace)" -ForegroundColor Red
        
        [System.Windows.Forms.MessageBox]::Show("Screen 2 Error: $($_.Exception.Message)`n`nPlease check the console for details.", "Screen Error", "OK", "Error")
        
        # Try to show Screen 1 again
        try {
            Show-Screen1
        }
        catch {
            Write-Host "Could not return to Screen 1: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Screen 3: Console Output Screen
function Show-Screen3 {
    Write-Host "=== Loading Screen 3: Rule Creation ===" -ForegroundColor Cyan
    $form = Get-MainForm
    Clear-FormControls -form $form
    $form.Text = "M365 Proofpoint IP Transport Rule Manager - Rule Creation"
    $form.Size = New-Object System.Drawing.Size(800, 500)
    
    # Title label
    $titleLabel = New-Object System.Windows.Forms.Label
    $titleLabel.Text = "Transport Rule Creation - Console Output"
    $titleLabel.Font = New-Object System.Drawing.Font("Arial", 16, [System.Drawing.FontStyle]::Bold)
    $titleLabel.Size = New-Object System.Drawing.Size(750, 30)
    $titleLabel.Location = New-Object System.Drawing.Point(25, 20)
    $titleLabel.TextAlign = "MiddleCenter"
    $titleLabel.ForeColor = [System.Drawing.Color]::DarkBlue
    $form.Controls.Add($titleLabel)
    
    # Process time notice
    $timeNoticeLabel = New-Object System.Windows.Forms.Label
    $timeNoticeLabel.Text = "This process may take up to 2 minutes"
    $timeNoticeLabel.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Italic)
    $timeNoticeLabel.Size = New-Object System.Drawing.Size(750, 20)
    $timeNoticeLabel.Location = New-Object System.Drawing.Point(25, 50)
    $timeNoticeLabel.TextAlign = "MiddleCenter"
    $timeNoticeLabel.ForeColor = [System.Drawing.Color]::Gray
    $form.Controls.Add($timeNoticeLabel)
    
    # Output text box
    $outputBox = New-Object System.Windows.Forms.TextBox
    $outputBox.Multiline = $true
    $outputBox.ScrollBars = "Vertical"
    $outputBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $outputBox.Size = New-Object System.Drawing.Size(720, 290)
    $outputBox.Location = New-Object System.Drawing.Point(40, 80)
    $outputBox.ReadOnly = $true
    $outputBox.BackColor = [System.Drawing.Color]::Black
    $outputBox.ForeColor = [System.Drawing.Color]::Green
    $form.Controls.Add($outputBox)
    
    # Progress bar
    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Size = New-Object System.Drawing.Size(720, 20)
    $progressBar.Location = New-Object System.Drawing.Point(40, 380)
    $progressBar.Style = "Marquee"
    $progressBar.MarqueeAnimationSpeed = 50
    $form.Controls.Add($progressBar)
    
    # Status label
    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Text = "Creating transport rule..."
    $statusLabel.Size = New-Object System.Drawing.Size(300, 20)
    $statusLabel.Location = New-Object System.Drawing.Point(40, 405)
    $form.Controls.Add($statusLabel)
    
    # Close button
    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = "Close"
    $closeButton.Size = New-Object System.Drawing.Size(100, 30)
    $closeButton.Location = New-Object System.Drawing.Point(350, 430)
    $closeButton.Enabled = $false
    $closeButton.Add_Click({
        # Return to Screen 2 after rule creation
        Show-Screen2
    })
    $form.Controls.Add($closeButton)
    
    # Start rule creation
    Write-Host "Starting rule creation process..." -ForegroundColor Green
    $form.Refresh()
    
    # Execute the transport rule creation
    try {
        $outputBox.AppendText("=== M365 Proofpoint Transport Rule Creation ===`r`n")
        $outputBox.AppendText("Starting transport rule creation...`r`n")
        $outputBox.AppendText("Rule Name: Block Messages from Unauthorized IPs`r`n")
        $outputBox.AppendText("Priority: 0`r`n")
        $outputBox.AppendText("Authorized IP Ranges: $($ProofpointIPs.Count) Proofpoint ranges`r`n")
        $outputBox.AppendText("`r`nIP Ranges being authorized:`r`n")
        foreach ($ip in $ProofpointIPs[0..4]) {
            $outputBox.AppendText("  - $ip`r`n")
        }
        $outputBox.AppendText("  ... and $($ProofpointIPs.Count - 5) more ranges`r`n")
        $outputBox.AppendText("`r`nExecuting New-TransportRule command...`r`n")
        $form.Refresh()
        
        # Execute the transport rule command
        $result = New-TransportRule -Name "Block Messages from Unauthorized IPs" -Priority 0 -ExceptIfSenderIpRanges $ProofpointIPs -ExceptIfHeaderContainsMessageHeader 'X-MS-Exchange-MeetingForward-Message' -ExceptIfHeaderContainsWords 'Forward' -RejectMessageReasonText "Unauthorized IP" -RejectMessageEnhancedStatusCode "5.7.1"
        
        $outputBox.AppendText("`r`n=== SUCCESS ===`r`n")
        $outputBox.AppendText("Transport rule created successfully!`r`n")
        $outputBox.AppendText("Rule Identity: $($result.Identity)`r`n")
        $outputBox.AppendText("Rule State: $($result.State)`r`n")
        $outputBox.AppendText("Priority: $($result.Priority)`r`n")
        $outputBox.AppendText("Reject Message Text: $($result.RejectMessageReasonText)`r`n")
        $outputBox.AppendText("Enhanced Status Code: $($result.RejectMessageEnhancedStatusCode)`r`n")
        $outputBox.AppendText("`r`nRule Configuration:`r`n")
        $outputBox.AppendText("- Blocks all emails from unauthorized IP addresses`r`n")
        $outputBox.AppendText("- Allows emails from $($ProofpointIPs.Count) Proofpoint IP ranges`r`n")
        $outputBox.AppendText("- Excludes meeting forward messages`r`n")
        $outputBox.AppendText("- Returns '5.7.1 Unauthorized IP' rejection message`r`n")
        $outputBox.AppendText("`r`nThe rule is now active and protecting your organization!`r`n")
        
        $statusLabel.Text = "Transport rule created successfully!"
        $statusLabel.ForeColor = [System.Drawing.Color]::Green
        $progressBar.Style = "Continuous"
        $progressBar.Value = 100
        $progressBar.BackColor = [System.Drawing.Color]::Green
        $closeButton.Enabled = $true
    }
    catch {
        $outputBox.AppendText("`r`n=== ERROR ===`r`n")
        $outputBox.AppendText("Failed to create transport rule!`r`n")
        $outputBox.AppendText("Error Details: $($_.Exception.Message)`r`n")
        $outputBox.AppendText("`r`nPossible causes:`r`n")
        $outputBox.AppendText("- Insufficient permissions (need Exchange Administrator role)`r`n")
        $outputBox.AppendText("- Network connectivity issues`r`n")
        $outputBox.AppendText("- Rule with same name already exists`r`n")
        $outputBox.AppendText("- Exchange Online connection expired`r`n")
        $outputBox.AppendText("`r`nPlease check the error details and try again.`r`n")
        
        $statusLabel.Text = "Error creating transport rule"
        $statusLabel.ForeColor = [System.Drawing.Color]::Red
        $progressBar.Visible = $false
        $closeButton.Enabled = $true
    }
    
    Write-Host "Screen 3 loaded successfully" -ForegroundColor Green
}

# Main execution starts here
try {
    Write-Host "M365 Proofpoint IP Transport Rule Manager" -ForegroundColor Cyan
    Write-Host "=======================================" -ForegroundColor Cyan
    Write-Host "Starting GUI application..." -ForegroundColor Green
    
    # Start the application with Screen 1
    Show-Screen1
    
    # Show the main form and keep it running
    $mainForm = Get-MainForm
    Write-Host "Starting main application loop..." -ForegroundColor Green
    $mainForm.ShowDialog() | Out-Null
}
catch {
    $errorMsg = "Application startup error: $($_.Exception.Message)"
    Write-Host $errorMsg -ForegroundColor Red
    [System.Windows.Forms.MessageBox]::Show($errorMsg, "Startup Error", "OK", "Error")
} 