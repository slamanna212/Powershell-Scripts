#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Generates reports of all IP addresses a user has logged in from by querying the Security Event Log.
    Can run in both GUI and command-line modes.

.DESCRIPTION
    This script queries the Windows Security Event Log on a domain controller to find all login events
    for a specified user and reports the IP addresses they have logged in from. This is useful for
    identifying all locations where a user account is being used before updating passwords or
    decommissioning accounts.
    
    The script can run in two modes:
    - GUI mode: Provides a Windows Forms interface (default when no parameters provided)
    - Console mode: Command-line interface with parameters

.PARAMETER Username
    The username to search for. If not provided in console mode, the script will prompt for it.

.PARAMETER Days
    Number of days to look back in the event log. Default is 30 days.

.PARAMETER OutputPath
    Optional path to save the report as a CSV file (console mode only).

.PARAMETER Console
    Force console/command-line mode instead of GUI mode.

.PARAMETER GUI
    Force GUI mode (this is the default when no parameters are provided).

.EXAMPLE
    .\UserLoginReport.ps1
    Launches in GUI mode
    
.EXAMPLE
    .\UserLoginReport.ps1 -Console
    Launches in console mode and prompts for username
    
.EXAMPLE
    .\UserLoginReport.ps1 -Console -Username "jdoe" -Days 60 -OutputPath "C:\Reports\jdoe_logins.csv"
    Runs in console mode with specified parameters

.NOTES
    - Must be run on a domain controller with administrator privileges
    - Requires access to the Security Event Log
    - Event ID 4624 (Successful Logon) and 4625 (Failed Logon) are queried
    - GUI mode uses Windows Forms interface
    - Console mode provides text-based output with optional CSV export
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Username,
    
    [Parameter(Mandatory=$false)]
    [int]$Days = 30,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$Console,
    
    [Parameter(Mandatory=$false)]
    [switch]$GUI
)

# Determine which mode to run in
$RunInGUI = $true
if ($Console) {
    $RunInGUI = $false
} elseif ($GUI) {
    $RunInGUI = $true
} elseif ($Username -or $OutputPath -or $PSBoundParameters.Count -gt 0) {
    # If any parameters are provided, assume console mode
    $RunInGUI = $false
}

# Try to detect if GUI is available
if ($RunInGUI) {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    }
    catch {
        Write-Warning "Windows Forms not available. Falling back to console mode."
        $RunInGUI = $false
    }
}

# Check if running as administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) {
    if ($RunInGUI) {
        try {
            [System.Windows.Forms.MessageBox]::Show("This application must be run as Administrator to access the Security Event Log.", "Administrator Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
        catch {
            Write-Error "This script must be run as Administrator to access the Security Event Log."
        }
    }
    else {
        Write-Error "This script must be run as Administrator to access the Security Event Log."
    }
    exit 1
}

# Common functions used by both modes
function Get-LoginEventsCommon {
    param(
        [string]$User,
        [int]$DaysBack,
        [System.Windows.Forms.ProgressBar]$ProgressBar = $null,
        [System.Windows.Forms.Label]$StatusLabel = $null
    )
    
    if ($StatusLabel) {
        $StatusLabel.Text = "Searching for login events for user: $User"
        $StatusLabel.Refresh()
    } else {
        Write-Host "Searching for login events for user: $User" -ForegroundColor Green
        Write-Host "Looking back $DaysBack days..." -ForegroundColor Yellow
    }
    
    $StartTime = (Get-Date).AddDays(-$DaysBack)
    $EventIds = @(4624, 4625)
    $Events = @()
    
    if ($ProgressBar) {
        $ProgressBar.Value = 10
        $ProgressBar.Refresh()
    }
    
    foreach ($EventId in $EventIds) {
        try {
            if ($StatusLabel) {
                $StatusLabel.Text = "Querying Event ID $EventId..."
                $StatusLabel.Refresh()
            } else {
                Write-Host "Querying Event ID $EventId..." -ForegroundColor Cyan
            }
            
            $FilterHashtable = @{
                LogName = 'Security'
                ID = $EventId
                StartTime = $StartTime
            }
            
            $EventResults = Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction SilentlyContinue
            
            if ($EventResults) {
                $Events += $EventResults
                if (-not $StatusLabel) {
                    Write-Host "Found $($EventResults.Count) events with ID $EventId" -ForegroundColor Green
                }
            }
        }
        catch {
            $ErrorMsg = "Error querying Event ID $EventId : $($_.Exception.Message)"
            if ($StatusLabel) {
                [System.Windows.Forms.MessageBox]::Show($ErrorMsg, "Warning", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            } else {
                Write-Warning $ErrorMsg
            }
        }
    }
    
    if ($ProgressBar) {
        $ProgressBar.Value = 30
        $ProgressBar.Refresh()
    }
    
    return $Events
}

function Parse-LoginEventsCommon {
    param(
        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]$Events,
        [string]$TargetUser,
        [System.Windows.Forms.ProgressBar]$ProgressBar = $null,
        [System.Windows.Forms.Label]$StatusLabel = $null
    )
    
    if ($StatusLabel) {
        $StatusLabel.Text = "Parsing events for user: $TargetUser"
        $StatusLabel.Refresh()
    } else {
        Write-Host "Parsing events for user: $TargetUser" -ForegroundColor Green
    }
    
    $LoginData = @()
    $ProcessedCount = 0
    $MatchedCount = 0
    $TotalEvents = $Events.Count
    
    foreach ($Event in $Events) {
        $ProcessedCount++
        
        # Update progress
        if ($ProgressBar -and $TotalEvents -gt 0) {
            $Progress = 30 + (($ProcessedCount / $TotalEvents) * 60)
            $ProgressBar.Value = [Math]::Min(90, $Progress)
            $ProgressBar.Refresh()
        }
        
        if ($ProcessedCount % 1000 -eq 0) {
            if ($StatusLabel) {
                $StatusLabel.Text = "Processed $ProcessedCount of $TotalEvents events..."
                $StatusLabel.Refresh()
            } else {
                Write-Host "Processed $ProcessedCount events..." -ForegroundColor Yellow
            }
        }
        
        try {
            $EventXml = [xml]$Event.ToXml()
            $EventData = $EventXml.Event.EventData.Data
            
            $EventInfo = @{}
            foreach ($Data in $EventData) {
                if ($Data.Name) {
                    $EventInfo[$Data.Name] = $Data.'#text'
                }
            }
            
            $EventUsername = $EventInfo['TargetUserName']
            if (-not $EventUsername) {
                $EventUsername = $EventInfo['SubjectUserName']
            }
            
            if ($EventUsername -and $EventUsername.ToLower() -eq $TargetUser.ToLower()) {
                $MatchedCount++
                
                $SourceIP = $EventInfo['IpAddress']
                if (-not $SourceIP) {
                    $SourceIP = $EventInfo['WorkstationName']
                }
                
                if ($SourceIP -and $SourceIP -ne '-' -and $SourceIP -ne '127.0.0.1' -and $SourceIP -ne '::1') {
                    
                    $LoginInfo = [PSCustomObject]@{
                        TimeStamp = $Event.TimeCreated
                        Username = $EventUsername
                        SourceIP = $SourceIP
                        EventID = $Event.Id
                        EventType = if ($Event.Id -eq 4624) { "Successful" } else { "Failed" }
                        LogonType = $EventInfo['LogonType']
                        WorkstationName = $EventInfo['WorkstationName']
                        ProcessName = $EventInfo['ProcessName']
                        AuthenticationPackageName = $EventInfo['AuthenticationPackageName']
                    }
                    
                    $LoginData += $LoginInfo
                }
            }
        }
        catch {
            # Silently continue on parsing errors
        }
    }
    
    if ($ProgressBar) {
        $ProgressBar.Value = 95
    }
    
    $StatusText = "Processed $ProcessedCount total events, found $MatchedCount matching events"
    if ($StatusLabel) {
        $StatusLabel.Text = $StatusText
        $StatusLabel.Refresh()
    } else {
        Write-Host $StatusText -ForegroundColor Green
    }
    
    return $LoginData
}

if ($RunInGUI) {
    # GUI Mode
    $Global:LoginData = @()
    $Global:CurrentUsername = ""
    $Global:CancelRequested = $false

    function Update-Results {
        param(
            [PSCustomObject[]]$LoginData,
            [System.Windows.Forms.DataGridView]$DataGrid,
            [System.Windows.Forms.ListBox]$IPListBox,
            [System.Windows.Forms.Label]$SummaryLabel
        )
        
        $DataGrid.Rows.Clear()
        $IPListBox.Items.Clear()
        
        if (-not $LoginData -or $LoginData.Count -eq 0) {
            $SummaryLabel.Text = "No login events found for the specified user."
            return
        }
        
        # Clean and normalize IP addresses before grouping
        $CleanedLoginData = $LoginData | ForEach-Object {
            # Create a copy and clean the SourceIP
            $CleanedEvent = $_ | Select-Object *
            $CleanedEvent.SourceIP = $_.SourceIP.ToString().Trim()
            $CleanedEvent
        }
        
        $IPSummary = $CleanedLoginData | Group-Object SourceIP | Sort-Object Count -Descending
        
        # Add debug information for troubleshooting
        Write-Host "Debug: Found $($LoginData.Count) total events grouped into $($IPSummary.Count) unique IP addresses" -ForegroundColor Cyan
        
        foreach ($IP in $IPSummary) {
            $SuccessfulLogins = ($IP.Group | Where-Object {$_.EventType -eq "Successful"}).Count
            $FailedLogins = ($IP.Group | Where-Object {$_.EventType -eq "Failed"}).Count
            $LastLogin = ($IP.Group | Sort-Object TimeStamp -Descending | Select-Object -First 1).TimeStamp
            
            # Debug output for first few IPs
            if ($IPSummary.IndexOf($IP) -lt 5) {
                Write-Host "Debug IP '$($IP.Name)': Count=$($IP.Count)" -ForegroundColor Yellow
            }
            
            $IPListBox.Items.Add("$($IP.Name) - Total: $($IP.Count) (Success: $SuccessfulLogins, Failed: $FailedLogins) - Last: $($LastLogin.ToString('yyyy-MM-dd HH:mm:ss'))")
        }
        
        $SortedData = $LoginData | Sort-Object TimeStamp -Descending | Select-Object -First 1000
        
        foreach ($Event in $SortedData) {
            $Row = $DataGrid.Rows.Add()
            $DataGrid.Rows[$Row].Cells[0].Value = $Event.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss')
            $DataGrid.Rows[$Row].Cells[1].Value = $Event.SourceIP
            $DataGrid.Rows[$Row].Cells[2].Value = $Event.EventType
            $DataGrid.Rows[$Row].Cells[3].Value = $Event.LogonType
            $DataGrid.Rows[$Row].Cells[4].Value = $Event.WorkstationName
            
            if ($Event.EventType -eq "Successful") {
                $DataGrid.Rows[$Row].DefaultCellStyle.BackColor = [System.Drawing.Color]::LightGreen
            } else {
                $DataGrid.Rows[$Row].DefaultCellStyle.BackColor = [System.Drawing.Color]::LightPink
            }
        }
        
        $UniqueIPs = $IPSummary.Count
        $TotalEvents = $LoginData.Count
        $SuccessfulTotal = ($LoginData | Where-Object {$_.EventType -eq "Successful"}).Count
        $FailedTotal = ($LoginData | Where-Object {$_.EventType -eq "Failed"}).Count
        
        $SummaryLabel.Text = "Summary: $UniqueIPs unique IP addresses, $TotalEvents total events ($SuccessfulTotal successful, $FailedTotal failed)"
    }

    function Export-ToCSV {
        param([PSCustomObject[]]$LoginData)
        
        if (-not $LoginData -or $LoginData.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No data to export!", "Export Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        
        $SaveDialog = New-Object System.Windows.Forms.SaveFileDialog
        $SaveDialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
        $SaveDialog.DefaultExt = "csv"
        $SaveDialog.FileName = "$Global:CurrentUsername-LoginReport-$(Get-Date -Format 'yyyyMMdd').csv"
        
        if ($SaveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $LoginData | Export-Csv -Path $SaveDialog.FileName -NoTypeInformation -Encoding UTF8
                [System.Windows.Forms.MessageBox]::Show("Report exported successfully to:`n$($SaveDialog.FileName)", "Export Complete", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to export report:`n$($_.Exception.Message)", "Export Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        }
    }

    # Create GUI
    $Form = New-Object System.Windows.Forms.Form
    $Form.Text = "User Login Report Generator"
    $Form.Size = New-Object System.Drawing.Size(1000, 700)
    $Form.StartPosition = "CenterScreen"
    $Form.FormBorderStyle = "FixedSingle"
    $Form.MaximizeBox = $false

    $TitleLabel = New-Object System.Windows.Forms.Label
    $TitleLabel.Text = "Domain Controller User Login Report Generator"
    $TitleLabel.Font = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Bold)
    $TitleLabel.Location = New-Object System.Drawing.Point(20, 20)
    $TitleLabel.Size = New-Object System.Drawing.Size(500, 30)
    $Form.Controls.Add($TitleLabel)

    $UsernameLabel = New-Object System.Windows.Forms.Label
    $UsernameLabel.Text = "Username:"
    $UsernameLabel.Location = New-Object System.Drawing.Point(20, 70)
    $UsernameLabel.Size = New-Object System.Drawing.Size(80, 20)
    $Form.Controls.Add($UsernameLabel)

    $UsernameTextBox = New-Object System.Windows.Forms.TextBox
    $UsernameTextBox.Location = New-Object System.Drawing.Point(100, 68)
    $UsernameTextBox.Size = New-Object System.Drawing.Size(200, 20)
    $Form.Controls.Add($UsernameTextBox)

    $DaysLabel = New-Object System.Windows.Forms.Label
    $DaysLabel.Text = "Days back:"
    $DaysLabel.Location = New-Object System.Drawing.Point(320, 70)
    $DaysLabel.Size = New-Object System.Drawing.Size(70, 20)
    $Form.Controls.Add($DaysLabel)

    $DaysNumeric = New-Object System.Windows.Forms.NumericUpDown
    $DaysNumeric.Location = New-Object System.Drawing.Point(390, 68)
    $DaysNumeric.Size = New-Object System.Drawing.Size(80, 20)
    $DaysNumeric.Minimum = 1
    $DaysNumeric.Maximum = 365
    $DaysNumeric.Value = 30
    $Form.Controls.Add($DaysNumeric)

    $SearchButton = New-Object System.Windows.Forms.Button
    $SearchButton.Text = "Generate Report"
    $SearchButton.Location = New-Object System.Drawing.Point(500, 66)
    $SearchButton.Size = New-Object System.Drawing.Size(120, 25)
    $SearchButton.BackColor = [System.Drawing.Color]::LightBlue
    $Form.Controls.Add($SearchButton)

    $ExportButton = New-Object System.Windows.Forms.Button
    $ExportButton.Text = "Export to CSV"
    $ExportButton.Location = New-Object System.Drawing.Point(640, 66)
    $ExportButton.Size = New-Object System.Drawing.Size(100, 25)
    $ExportButton.BackColor = [System.Drawing.Color]::LightGreen
    $ExportButton.Enabled = $false
    $Form.Controls.Add($ExportButton)

    $ProgressBar = New-Object System.Windows.Forms.ProgressBar
    $ProgressBar.Location = New-Object System.Drawing.Point(20, 110)
    $ProgressBar.Size = New-Object System.Drawing.Size(720, 20)
    $ProgressBar.Style = "Continuous"
    $Form.Controls.Add($ProgressBar)

    $StatusLabel = New-Object System.Windows.Forms.Label
    $StatusLabel.Text = "Ready. Enter a username and click 'Generate Report' to begin."
    $StatusLabel.Location = New-Object System.Drawing.Point(20, 140)
    $StatusLabel.Size = New-Object System.Drawing.Size(720, 20)
    $Form.Controls.Add($StatusLabel)

    # Warning label about responsiveness
    $WarningLabel = New-Object System.Windows.Forms.Label
    $WarningLabel.Text = "Windows may show this app as 'Not Responding' during large event log queries. This is normal - please wait for completion."
    $WarningLabel.Location = New-Object System.Drawing.Point(20, 160)
    $WarningLabel.Size = New-Object System.Drawing.Size(720, 30)
    $WarningLabel.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Italic)
    $WarningLabel.ForeColor = [System.Drawing.Color]::DarkRed
    $WarningLabel.Visible = $false  # Hidden by default, shown during processing
    $Form.Controls.Add($WarningLabel)

    $SummaryLabel = New-Object System.Windows.Forms.Label
    $SummaryLabel.Text = ""
    $SummaryLabel.Location = New-Object System.Drawing.Point(20, 190)
    $SummaryLabel.Size = New-Object System.Drawing.Size(720, 20)
    $SummaryLabel.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
    $Form.Controls.Add($SummaryLabel)

    $TabControl = New-Object System.Windows.Forms.TabControl
    $TabControl.Location = New-Object System.Drawing.Point(20, 220)
    $TabControl.Size = New-Object System.Drawing.Size(950, 420)
    $Form.Controls.Add($TabControl)

    $IPTab = New-Object System.Windows.Forms.TabPage
    $IPTab.Text = "IP Address Summary"
    $TabControl.TabPages.Add($IPTab)

    $IPListBox = New-Object System.Windows.Forms.ListBox
    $IPListBox.Location = New-Object System.Drawing.Point(10, 10)
    $IPListBox.Size = New-Object System.Drawing.Size(920, 400)
    $IPListBox.Font = New-Object System.Drawing.Font("Consolas", 9)
    $IPTab.Controls.Add($IPListBox)

    $EventsTab = New-Object System.Windows.Forms.TabPage
    $EventsTab.Text = "Detailed Events"
    $TabControl.TabPages.Add($EventsTab)

    $DataGrid = New-Object System.Windows.Forms.DataGridView
    $DataGrid.Location = New-Object System.Drawing.Point(10, 10)
    $DataGrid.Size = New-Object System.Drawing.Size(920, 400)
    $DataGrid.AllowUserToAddRows = $false
    $DataGrid.AllowUserToDeleteRows = $false
    $DataGrid.ReadOnly = $true
    $DataGrid.AutoSizeColumnsMode = "Fill"
    $DataGrid.SelectionMode = "FullRowSelect"

    $DataGrid.Columns.Add("TimeStamp", "Timestamp")
    $DataGrid.Columns.Add("SourceIP", "Source IP")
    $DataGrid.Columns.Add("EventType", "Event Type")
    $DataGrid.Columns.Add("LogonType", "Logon Type")
    $DataGrid.Columns.Add("WorkstationName", "Workstation")

    $EventsTab.Controls.Add($DataGrid)

    # Create a timer to keep GUI responsive during blocking operations
    $Global:UpdateTimer = New-Object System.Windows.Forms.Timer
    $Global:UpdateTimer.Interval = 50  # Update every 50ms (more aggressive)
    $Global:UpdateTimer.Add_Tick({
        [System.Windows.Forms.Application]::DoEvents()
        # Force a repaint to prevent "Not Responding"
        $Form.Refresh()
    })

    # Helper function to keep GUI responsive
    function Update-GUI {
        [System.Windows.Forms.Application]::DoEvents()
        $Form.Refresh()
        Start-Sleep -Milliseconds 5  # Shorter sleep
    }

    # Function to start responsive mode
    function Start-ResponsiveMode {
        $Global:UpdateTimer.Start()
    }

    # Function to stop responsive mode
    function Stop-ResponsiveMode {
        $Global:UpdateTimer.Stop()
    }

    # Function to process events with GUI responsiveness
    function Get-LoginEventsGUI {
        param(
            [string]$User,
            [int]$DaysBack
        )
        
        # Start the responsive timer
        Start-ResponsiveMode
        
        try {
            $StatusLabel.Text = "Initializing search for user: $User"
            $ProgressBar.Value = 5
            Update-GUI
            
            if ($Global:CancelRequested) { return $null }
            
            $StatusLabel.Text = "Querying Event ID 4624 (Successful Logons)... This may take several minutes for large logs."
            $ProgressBar.Value = 10
            $ProgressBar.Style = "Marquee"  # Show continuous animation during blocking operation
            Update-GUI
            
            $StartTime = (Get-Date).AddDays(-$DaysBack)
            $Events = @()
            
            # Query Event ID 4624 (Successful Logons)
            try {
                $FilterHashtable = @{
                    LogName = 'Security'
                    ID = 4624
                    StartTime = $StartTime
                }
                
                $EventResults4624 = Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction SilentlyContinue
                if ($EventResults4624) {
                    $Events += $EventResults4624
                    $StatusLabel.Text = "Found $($EventResults4624.Count) successful logon events."
                    Update-GUI
                }
            }
            catch {
                # Continue even if there's an error with this event ID
            }
            
            if ($Global:CancelRequested) { return $null }
            
            $StatusLabel.Text = "Querying Event ID 4625 (Failed Logons)... This may take several minutes for large logs."
            Update-GUI
            
            # Query Event ID 4625 (Failed Logons)
            try {
                $FilterHashtable = @{
                    LogName = 'Security'
                    ID = 4625
                    StartTime = $StartTime
                }
                
                $EventResults4625 = Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction SilentlyContinue
                if ($EventResults4625) {
                    $Events += $EventResults4625
                    $StatusLabel.Text = "Found $($EventResults4625.Count) failed logon events."
                    Update-GUI
                }
            }
            catch {
                # Continue even if there's an error with this event ID
            }
            
            if ($Global:CancelRequested) { return $null }
            
            $StatusLabel.Text = "Found $($Events.Count) total events. Starting analysis..."
            $ProgressBar.Style = "Continuous"  # Switch back to normal progress bar
            $ProgressBar.Value = 30
            Update-GUI
        
        if (-not $Events -or $Events.Count -eq 0) {
            return @()
        }
        
        # Parse events with GUI responsiveness
        $LoginData = @()
        $ProcessedCount = 0
        $MatchedCount = 0
        $TotalEvents = $Events.Count
        
        foreach ($Event in $Events) {
            if ($Global:CancelRequested) { return $null }
            
            $ProcessedCount++
            
                        # Update progress and keep GUI responsive every 50 events (more frequent)
            if ($ProcessedCount % 50 -eq 0) {
                $Progress = 30 + (($ProcessedCount / $TotalEvents) * 60)
                $ProgressBar.Value = [Math]::Min(90, $Progress)
                $StatusLabel.Text = "Processed $ProcessedCount of $TotalEvents events... ($MatchedCount matches found)"
                Update-GUI
            }
            
            try {
                $EventXml = [xml]$Event.ToXml()
                $EventData = $EventXml.Event.EventData.Data
                
                $EventInfo = @{}
                foreach ($Data in $EventData) {
                    if ($Data.Name) {
                        $EventInfo[$Data.Name] = $Data.'#text'
                    }
                }
                
                $EventUsername = $EventInfo['TargetUserName']
                if (-not $EventUsername) {
                    $EventUsername = $EventInfo['SubjectUserName']
                }
                
                if ($EventUsername -and $EventUsername.ToLower() -eq $User.ToLower()) {
                    $MatchedCount++
                    
                    $SourceIP = $EventInfo['IpAddress']
                    if (-not $SourceIP) {
                        $SourceIP = $EventInfo['WorkstationName']
                    }
                    
                    if ($SourceIP -and $SourceIP -ne '-' -and $SourceIP -ne '127.0.0.1' -and $SourceIP -ne '::1') {
                        
                        # Clean and normalize the SourceIP
                        $CleanSourceIP = $SourceIP.ToString().Trim()
                        
                        # Skip if empty after trimming
                        if ([string]::IsNullOrWhiteSpace($CleanSourceIP)) {
                            continue
                        }
                        
                        $LoginInfo = [PSCustomObject]@{
                            TimeStamp = $Event.TimeCreated
                            Username = $EventUsername
                            SourceIP = $CleanSourceIP
                            EventID = $Event.Id
                            EventType = if ($Event.Id -eq 4624) { "Successful" } else { "Failed" }
                            LogonType = $EventInfo['LogonType']
                            WorkstationName = if ($EventInfo['WorkstationName']) { $EventInfo['WorkstationName'].ToString().Trim() } else { "" }
                            ProcessName = if ($EventInfo['ProcessName']) { $EventInfo['ProcessName'].ToString().Trim() } else { "" }
                            AuthenticationPackageName = if ($EventInfo['AuthenticationPackageName']) { $EventInfo['AuthenticationPackageName'].ToString().Trim() } else { "" }
                        }
                        
                        $LoginData += $LoginInfo
                    }
                }
            }
            catch {
                # Silently continue on parsing errors
            }
        }
        
            if ($Global:CancelRequested) { return $null }
            
            $StatusLabel.Text = "Analysis complete. Found $MatchedCount matching events for user $User"
            $ProgressBar.Value = 95
            Update-GUI
            
            return $LoginData
            
        }
        finally {
            # Always stop the responsive timer
            Stop-ResponsiveMode
        }
    }

    # Search button click event
    $SearchButton.Add_Click({
        if ([string]::IsNullOrWhiteSpace($UsernameTextBox.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Please enter a username.", "Input Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        
        # Check if cancel was requested
        if ($Global:CancelRequested) {
            $Global:CancelRequested = $false
            $SearchButton.Text = "Generate Report"
            $SearchButton.Enabled = $true
            $UsernameTextBox.Enabled = $true
            $DaysNumeric.Enabled = $true
            $StatusLabel.Text = "Operation cancelled."
            $ProgressBar.Value = 0
            return
        }
        
        # Check if currently processing
        if ($SearchButton.Text -eq "Cancel") {
            $Global:CancelRequested = $true
            $SearchButton.Text = "Cancelling..."
            $SearchButton.Enabled = $false
            return
        }
        
        # Start new operation
        $Global:CurrentUsername = $UsernameTextBox.Text.Trim()
        $Days = [int]$DaysNumeric.Value
        $Global:CancelRequested = $false
        
        # Disable controls during search
        $SearchButton.Text = "Cancel"
        $ExportButton.Enabled = $false
        $UsernameTextBox.Enabled = $false
        $DaysNumeric.Enabled = $false
        
        # Show warning about responsiveness
        $WarningLabel.Visible = $true
        
        # Clear previous results
        $DataGrid.Rows.Clear()
        $IPListBox.Items.Clear()
        $SummaryLabel.Text = ""
        $ProgressBar.Value = 0
        
        try {
            # Process events with GUI responsiveness
            $Global:LoginData = Get-LoginEventsGUI -User $Global:CurrentUsername -DaysBack $Days
            
            if ($Global:CancelRequested) {
                $StatusLabel.Text = "Operation was cancelled."
                $SummaryLabel.Text = ""
                $ProgressBar.Value = 0
            }
            elseif ($null -eq $Global:LoginData) {
                $StatusLabel.Text = "Operation was cancelled."
                $SummaryLabel.Text = ""
                $ProgressBar.Value = 0
            }
            elseif ($Global:LoginData.Count -eq 0) {
                $StatusLabel.Text = "No login events found in the specified time period."
                $SummaryLabel.Text = "No events found."
                $ProgressBar.Value = 0
            }
            else {
                # Update results
                Update-Results -LoginData $Global:LoginData -DataGrid $DataGrid -IPListBox $IPListBox -SummaryLabel $SummaryLabel
                $ExportButton.Enabled = $true
                $ProgressBar.Value = 100
                $StatusLabel.Text = "Report generation completed successfully. Found $($Global:LoginData.Count) login events."
            }
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("An error occurred: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            $StatusLabel.Text = "Error occurred during report generation."
            $ProgressBar.Value = 0
        }
        finally {
            # Always stop the responsive timer
            Stop-ResponsiveMode
            
            # Hide warning
            $WarningLabel.Visible = $false
            
            # Re-enable controls
            $SearchButton.Text = "Generate Report"
            $SearchButton.Enabled = $true
            $UsernameTextBox.Enabled = $true
            $DaysNumeric.Enabled = $true
            $Global:CancelRequested = $false
        }
    })

    $ExportButton.Add_Click({
        Export-ToCSV -LoginData $Global:LoginData
    })

    $UsernameTextBox.Add_KeyDown({
        if ($_.KeyCode -eq "Enter") {
            $SearchButton.PerformClick()
        }
    })

    $Form.Add_Shown({$Form.Activate()})
    [System.Windows.Forms.Application]::Run($Form)
}
else {
    # Console Mode
    function Get-UsernameInput {
        if (-not $Username) {
            do {
                $script:Username = Read-Host "Enter the username to search for"
            } while ([string]::IsNullOrWhiteSpace($Username))
        }
    }

    function Generate-ConsoleReport {
        param(
            [PSCustomObject[]]$LoginData,
            [string]$User,
            [string]$OutputFile
        )
        
        if (-not $LoginData -or $LoginData.Count -eq 0) {
            Write-Host "No login events found for user: $User" -ForegroundColor Red
            return
        }
        
        Write-Host "`n" -NoNewline
        Write-Host "=" * 80 -ForegroundColor Cyan
        Write-Host "LOGIN REPORT FOR USER: $($User.ToUpper())" -ForegroundColor Cyan
        Write-Host "=" * 80 -ForegroundColor Cyan
        Write-Host "Report Generated: $(Get-Date)" -ForegroundColor Yellow
        Write-Host "Total Login Events Found: $($LoginData.Count)" -ForegroundColor Yellow
        Write-Host ""
        
        # Clean and normalize IP addresses before grouping (same as GUI mode)
        $CleanedLoginData = $LoginData | ForEach-Object {
            $CleanedEvent = $_ | Select-Object *
            $CleanedEvent.SourceIP = $_.SourceIP.ToString().Trim()
            $CleanedEvent
        }
        
        $IPSummary = $CleanedLoginData | Group-Object SourceIP | Sort-Object Count -Descending
        
        Write-Host "UNIQUE IP ADDRESSES ($($IPSummary.Count) total):" -ForegroundColor Green
        Write-Host "-" * 50 -ForegroundColor Green
        
        foreach ($IP in $IPSummary) {
            $SuccessfulLogins = ($IP.Group | Where-Object {$_.EventType -eq "Successful"}).Count
            $FailedLogins = ($IP.Group | Where-Object {$_.EventType -eq "Failed"}).Count
            $LastLogin = ($IP.Group | Sort-Object TimeStamp -Descending | Select-Object -First 1).TimeStamp
            
            Write-Host "IP: $($IP.Name)" -ForegroundColor White
            Write-Host "  Total Attempts: $($IP.Count) (Success: $SuccessfulLogins, Failed: $FailedLogins)" -ForegroundColor Gray
            Write-Host "  Last Activity: $LastLogin" -ForegroundColor Gray
            Write-Host ""
        }
        
        Write-Host "DETAILED LOGIN EVENTS:" -ForegroundColor Green
        Write-Host "-" * 50 -ForegroundColor Green
        
        $SortedData = $LoginData | Sort-Object TimeStamp -Descending
        
        foreach ($Event in $SortedData | Select-Object -First 50) {
            $Color = if ($Event.EventType -eq "Successful") { "Green" } else { "Red" }
            Write-Host "$($Event.TimeStamp) - $($Event.SourceIP) - $($Event.EventType)" -ForegroundColor $Color
        }
        
        if ($LoginData.Count -gt 50) {
            Write-Host "... and $($LoginData.Count - 50) more events" -ForegroundColor Yellow
        }
        
        if ($OutputFile) {
            try {
                $LoginData | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
                Write-Host "`nReport saved to: $OutputFile" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to save report to $OutputFile : $($_.Exception.Message)"
            }
        }
        
        Write-Host "`nSUMMARY:" -ForegroundColor Cyan
        Write-Host "- User '$User' has logged in from $($IPSummary.Count) unique IP addresses" -ForegroundColor White
        Write-Host "- Total login events: $($LoginData.Count)" -ForegroundColor White
        Write-Host "- Successful logins: $(($LoginData | Where-Object {$_.EventType -eq 'Successful'}).Count)" -ForegroundColor Green
        Write-Host "- Failed logins: $(($LoginData | Where-Object {$_.EventType -eq 'Failed'}).Count)" -ForegroundColor Red
        Write-Host "=" * 80 -ForegroundColor Cyan
    }

    try {
        Clear-Host
        Write-Host "PowerShell User Login Report Generator (Console Mode)" -ForegroundColor Cyan
        Write-Host "====================================================" -ForegroundColor Cyan
        Write-Host ""
        
        Get-UsernameInput
        
        Write-Host "Configuration:" -ForegroundColor Yellow
        Write-Host "- Username: $Username" -ForegroundColor White
        Write-Host "- Days to search: $Days" -ForegroundColor White
        Write-Host "- Output file: $(if ($OutputPath) { $OutputPath } else { 'Console only' })" -ForegroundColor White
        Write-Host ""
        
        $Events = Get-LoginEventsCommon -User $Username -DaysBack $Days
        
        if (-not $Events -or $Events.Count -eq 0) {
            Write-Host "No login events found in the specified time period." -ForegroundColor Red
            exit 0
        }
        
        $LoginData = Parse-LoginEventsCommon -Events $Events -TargetUser $Username
        
        Generate-ConsoleReport -LoginData $LoginData -User $Username -OutputFile $OutputPath
        
    }
    catch {
        Write-Error "An error occurred: $($_.Exception.Message)"
        Write-Host "Stack Trace:" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
        exit 1
    }

    Write-Host "`nScript completed successfully!" -ForegroundColor Green
} 