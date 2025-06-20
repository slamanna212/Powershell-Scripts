#Requires -RunAsAdministrator
<#
.SYNOPSIS
    GUI-based tool to generate reports of all IP addresses a user has logged in from.

.DESCRIPTION
    This script provides a Windows Forms GUI interface to query the Windows Security Event Log 
    on a domain controller and find all login events for a specified user, reporting the IP 
    addresses they have logged in from. Useful for identifying all locations where a user 
    account is being used before updating passwords or decommissioning accounts.

.NOTES
    - Must be run on a domain controller with administrator privileges
    - Requires access to the Security Event Log
    - Event ID 4624 (Successful Logon) and 4625 (Failed Logon) are queried
    - GUI-only application with built-in debug output tab
#>

# Load required assemblies
try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
}
catch {
    Write-Error "Windows Forms not available. This script requires a GUI environment."
    exit 1
}

# Check if running as administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) {
    [System.Windows.Forms.MessageBox]::Show("This application must be run as Administrator to access the Security Event Log.", "Administrator Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}

# Global variables
$Global:LoginData = @()
$Global:CurrentUsername = ""
$Global:CancelRequested = $false
$Global:UpdateTimer = $null
$Global:DebugOutput = $null

# Function to add debug output
function Add-DebugOutput {
    param([string]$Message)
    
    $Timestamp = Get-Date -Format "HH:mm:ss"
    $DebugMessage = "[$Timestamp] $Message"
    
    if ($Global:DebugOutput) {
        $Global:DebugOutput.AppendText("$DebugMessage`r`n")
        $Global:DebugOutput.ScrollToCaret()
        $Global:DebugOutput.Refresh()
    }
}

# Function to get login events
function Get-LoginEvents {
    param(
        [string]$User,
        [int]$DaysBack,
        [System.Windows.Forms.ProgressBar]$ProgressBar,
        [System.Windows.Forms.Label]$StatusLabel
    )
    
    Add-DebugOutput "Starting search for user: $User"
    Add-DebugOutput "Looking back $DaysBack days"
    
    $StatusLabel.Text = "Searching for login events..."
    $StatusLabel.Refresh()
    
    # Set progress bar to marquee mode for indeterminate progress
    $ProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Marquee
    $ProgressBar.MarqueeAnimationSpeed = 30
    $ProgressBar.Visible = $true
    [System.Windows.Forms.Application]::DoEvents()
    
    $StartTime = (Get-Date).AddDays(-$DaysBack)
    $EventIds = @(4624, 4625)
    $Events = @()
    
    foreach ($EventId in $EventIds) {
        try {
            Add-DebugOutput "Querying Event ID $EventId..."
            $StatusLabel.Text = "Querying Event ID $EventId..."
            $StatusLabel.Refresh()
            [System.Windows.Forms.Application]::DoEvents()
            
            $FilterHashtable = @{
                LogName = 'Security'
                ID = $EventId
                StartTime = $StartTime
            }
            
            $EventResults = Get-WinEvent -FilterHashtable $FilterHashtable -ErrorAction SilentlyContinue
            
            if ($EventResults) {
                $Events += $EventResults
                Add-DebugOutput "Found $($EventResults.Count) events with ID $EventId"
            } else {
                Add-DebugOutput "No events found with ID $EventId"
            }
        }
        catch {
            $ErrorMsg = "Error querying Event ID $EventId : $($_.Exception.Message)"
            Add-DebugOutput "ERROR: $ErrorMsg"
        }
    }
    
    Add-DebugOutput "Total events retrieved: $($Events.Count)"
    return $Events
}

# Function to parse login events
function Parse-LoginEvents {
    param(
        [array]$Events,
        [string]$TargetUser,
        [System.Windows.Forms.ProgressBar]$ProgressBar,
        [System.Windows.Forms.Label]$StatusLabel
    )
    
    Add-DebugOutput "Parsing events for user: $TargetUser"
    
    $LoginData = @()
    $ProcessedCount = 0
    $MatchedCount = 0
    $TotalEvents = $Events.Count
    
    # Switch to continuous progress bar for parsing with known count
    $ProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
    $ProgressBar.Minimum = 0
    $ProgressBar.Maximum = 100
    $ProgressBar.Value = 0
    $StatusLabel.Text = "Parsing events..."
    $StatusLabel.Refresh()
    [System.Windows.Forms.Application]::DoEvents()
    
    foreach ($Event in $Events) {
        $ProcessedCount++
        
        # Update progress bar and status
        if ($TotalEvents -gt 0) {
            $ProgressPercent = [Math]::Min(99, [Math]::Round(($ProcessedCount / $TotalEvents) * 100))
            $ProgressBar.Value = $ProgressPercent
        }
        
        if ($ProcessedCount % 1000 -eq 0) {
            $StatusLabel.Text = "Processed $ProcessedCount of $TotalEvents events..."
            $StatusLabel.Refresh()
            [System.Windows.Forms.Application]::DoEvents()
            Add-DebugOutput "Processed $ProcessedCount events..."
        }
        
        # Keep UI responsive during processing
        if ($ProcessedCount % 250 -eq 0) {
            [System.Windows.Forms.Application]::DoEvents()
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
                        SourceIP = $SourceIP.ToString().Trim()
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
            Add-DebugOutput "Error parsing event: $($_.Exception.Message)"
        }
    }
    
    Add-DebugOutput "Processed $ProcessedCount total events, found $MatchedCount matching events"
    Add-DebugOutput "Login data entries created: $($LoginData.Count)"
    
    return $LoginData
}

# Function to update results
function Update-Results {
    param(
        [array]$LoginData,
        [System.Windows.Forms.DataGridView]$IPSummaryGrid,
        [System.Windows.Forms.DataGridView]$DetailGrid,
        [System.Windows.Forms.Label]$SummaryLabel
    )
    
    Add-DebugOutput "Updating results display..."
    
    $IPSummaryGrid.Rows.Clear()
    $DetailGrid.Rows.Clear()
    
    if (-not $LoginData -or $LoginData.Count -eq 0) {
        $SummaryLabel.Text = "No login events found for the specified user."
        Add-DebugOutput "No login data to display"
        return
    }
    
    # Group by IP address
    $IPSummary = $LoginData | Group-Object SourceIP | Sort-Object Count -Descending
    
    Add-DebugOutput "Grouped into $($IPSummary.Count) unique IP addresses"
    
    # Populate IP Summary tab
    foreach ($IP in $IPSummary) {
        $SuccessfulLogins = ($IP.Group | Where-Object {$_.EventType -eq "Successful"}).Count
        $FailedLogins = ($IP.Group | Where-Object {$_.EventType -eq "Failed"}).Count
        $LastLogin = ($IP.Group | Sort-Object TimeStamp -Descending | Select-Object -First 1).TimeStamp
        
        $Row = $IPSummaryGrid.Rows.Add()
        $IPSummaryGrid.Rows[$Row].Cells[0].Value = $IP.Name
        $IPSummaryGrid.Rows[$Row].Cells[1].Value = $IP.Count
        $IPSummaryGrid.Rows[$Row].Cells[2].Value = $SuccessfulLogins
        $IPSummaryGrid.Rows[$Row].Cells[3].Value = $FailedLogins
        $IPSummaryGrid.Rows[$Row].Cells[4].Value = $LastLogin.ToString('yyyy-MM-dd HH:mm:ss')
    }
    
    # Populate Detailed Events tab (limit to most recent 1000)
    $SortedData = $LoginData | Sort-Object TimeStamp -Descending | Select-Object -First 1000
    
    foreach ($Event in $SortedData) {
        $Row = $DetailGrid.Rows.Add()
        $DetailGrid.Rows[$Row].Cells[0].Value = $Event.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss')
        $DetailGrid.Rows[$Row].Cells[1].Value = $Event.SourceIP
        $DetailGrid.Rows[$Row].Cells[2].Value = $Event.EventType
        $DetailGrid.Rows[$Row].Cells[3].Value = $Event.LogonType
        $DetailGrid.Rows[$Row].Cells[4].Value = $Event.WorkstationName
        
        if ($Event.EventType -eq "Successful") {
            $DetailGrid.Rows[$Row].DefaultCellStyle.BackColor = [System.Drawing.Color]::LightGreen
        } else {
            $DetailGrid.Rows[$Row].DefaultCellStyle.BackColor = [System.Drawing.Color]::LightPink
        }
    }
    
    $UniqueIPs = $IPSummary.Count
    $TotalEvents = $LoginData.Count
    $SuccessfulTotal = ($LoginData | Where-Object {$_.EventType -eq "Successful"}).Count
    $FailedTotal = ($LoginData | Where-Object {$_.EventType -eq "Failed"}).Count
    
    $SummaryLabel.Text = "Summary: $UniqueIPs unique IP addresses, $TotalEvents total events ($SuccessfulTotal successful, $FailedTotal failed)"
    Add-DebugOutput "Results updated successfully"
}

# Function to export to CSV
function Export-ToCSV {
    param([array]$LoginData)
    
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

# Create the main form
$Form = New-Object System.Windows.Forms.Form
$Form.Text = "User Login Report Generator"
$Form.Size = New-Object System.Drawing.Size(1000, 700)
$Form.StartPosition = "CenterScreen"
$Form.FormBorderStyle = "FixedSingle"
$Form.MaximizeBox = $false

# Title
$TitleLabel = New-Object System.Windows.Forms.Label
$TitleLabel.Text = "Domain Controller User Login Report Generator"
$TitleLabel.Font = New-Object System.Drawing.Font("Arial", 14, [System.Drawing.FontStyle]::Bold)
$TitleLabel.Location = New-Object System.Drawing.Point(20, 20)
$TitleLabel.Size = New-Object System.Drawing.Size(500, 30)
$Form.Controls.Add($TitleLabel)

# Input controls
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

# Progress bar and status
$ProgressBar = New-Object System.Windows.Forms.ProgressBar
$ProgressBar.Location = New-Object System.Drawing.Point(20, 110)
$ProgressBar.Size = New-Object System.Drawing.Size(720, 20)
$ProgressBar.Style = "Continuous"
$ProgressBar.Minimum = 0
$ProgressBar.Maximum = 100
$ProgressBar.Value = 0
$ProgressBar.Visible = $true
$Form.Controls.Add($ProgressBar)

$StatusLabel = New-Object System.Windows.Forms.Label
$StatusLabel.Text = "Ready to generate report..."
$StatusLabel.Location = New-Object System.Drawing.Point(20, 140)
$StatusLabel.Size = New-Object System.Drawing.Size(720, 20)
$Form.Controls.Add($StatusLabel)

# Tab control
$TabControl = New-Object System.Windows.Forms.TabControl
$TabControl.Location = New-Object System.Drawing.Point(20, 170)
$TabControl.Size = New-Object System.Drawing.Size(950, 450)
$Form.Controls.Add($TabControl)

# IP Summary Tab
$IPSummaryTab = New-Object System.Windows.Forms.TabPage
$IPSummaryTab.Text = "IP Address Summary"
$TabControl.TabPages.Add($IPSummaryTab)

$IPSummaryGrid = New-Object System.Windows.Forms.DataGridView
$IPSummaryGrid.Location = New-Object System.Drawing.Point(10, 10)
$IPSummaryGrid.Size = New-Object System.Drawing.Size(920, 400)
$IPSummaryGrid.AllowUserToAddRows = $false
$IPSummaryGrid.AllowUserToDeleteRows = $false
$IPSummaryGrid.ReadOnly = $true
$IPSummaryGrid.SelectionMode = "FullRowSelect"
$IPSummaryGrid.Columns.Add("IP", "IP Address") | Out-Null
$IPSummaryGrid.Columns.Add("Total", "Total Events") | Out-Null
$IPSummaryGrid.Columns.Add("Successful", "Successful") | Out-Null
$IPSummaryGrid.Columns.Add("Failed", "Failed") | Out-Null
$IPSummaryGrid.Columns.Add("LastLogin", "Last Login") | Out-Null
$IPSummaryGrid.Columns["IP"].Width = 150
$IPSummaryGrid.Columns["Total"].Width = 100
$IPSummaryGrid.Columns["Successful"].Width = 100
$IPSummaryGrid.Columns["Failed"].Width = 100
$IPSummaryGrid.Columns["LastLogin"].Width = 200
$IPSummaryTab.Controls.Add($IPSummaryGrid)

# Detailed Events Tab
$DetailTab = New-Object System.Windows.Forms.TabPage
$DetailTab.Text = "Detailed Events"
$TabControl.TabPages.Add($DetailTab)

$DetailGrid = New-Object System.Windows.Forms.DataGridView
$DetailGrid.Location = New-Object System.Drawing.Point(10, 10)
$DetailGrid.Size = New-Object System.Drawing.Size(920, 400)
$DetailGrid.AllowUserToAddRows = $false
$DetailGrid.AllowUserToDeleteRows = $false
$DetailGrid.ReadOnly = $true
$DetailGrid.SelectionMode = "FullRowSelect"
$DetailGrid.Columns.Add("TimeStamp", "Time") | Out-Null
$DetailGrid.Columns.Add("SourceIP", "Source IP") | Out-Null
$DetailGrid.Columns.Add("EventType", "Event Type") | Out-Null
$DetailGrid.Columns.Add("LogonType", "Logon Type") | Out-Null
$DetailGrid.Columns.Add("WorkstationName", "Workstation") | Out-Null
$DetailGrid.Columns["TimeStamp"].Width = 150
$DetailGrid.Columns["SourceIP"].Width = 150
$DetailGrid.Columns["EventType"].Width = 100
$DetailGrid.Columns["LogonType"].Width = 100
$DetailGrid.Columns["WorkstationName"].Width = 150
$DetailTab.Controls.Add($DetailGrid)

# Debug Output Tab
$DebugTab = New-Object System.Windows.Forms.TabPage
$DebugTab.Text = "Debug Output"
$TabControl.TabPages.Add($DebugTab)

$Global:DebugOutput = New-Object System.Windows.Forms.TextBox
$Global:DebugOutput.Location = New-Object System.Drawing.Point(10, 10)
$Global:DebugOutput.Size = New-Object System.Drawing.Size(920, 400)
$Global:DebugOutput.Multiline = $true
$Global:DebugOutput.ScrollBars = "Vertical"
$Global:DebugOutput.ReadOnly = $true
$Global:DebugOutput.Font = New-Object System.Drawing.Font("Consolas", 9)
$DebugTab.Controls.Add($Global:DebugOutput)

# Summary label
$SummaryLabel = New-Object System.Windows.Forms.Label
$SummaryLabel.Text = "No report generated yet."
$SummaryLabel.Location = New-Object System.Drawing.Point(20, 630)
$SummaryLabel.Size = New-Object System.Drawing.Size(950, 20)
$SummaryLabel.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
$Form.Controls.Add($SummaryLabel)

# Event handlers
$SearchButton.Add_Click({
    if ([string]::IsNullOrWhiteSpace($UsernameTextBox.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a username.", "Missing Input", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    $Global:CurrentUsername = $UsernameTextBox.Text.Trim()
    $Days = [int]$DaysNumeric.Value
    
    # Clear debug output
    $Global:DebugOutput.Clear()
    Add-DebugOutput "Starting new search for user: $Global:CurrentUsername"
    
    # Disable controls
    $SearchButton.Enabled = $false
    $ExportButton.Enabled = $false
    $UsernameTextBox.Enabled = $false
    $DaysNumeric.Enabled = $false
    
    try {
        # Get events
        $Events = Get-LoginEvents -User $Global:CurrentUsername -DaysBack $Days -ProgressBar $ProgressBar -StatusLabel $StatusLabel
        
        if ($Events -and $Events.Count -gt 0) {
            # Parse events
            $Global:LoginData = Parse-LoginEvents -Events $Events -TargetUser $Global:CurrentUsername -ProgressBar $ProgressBar -StatusLabel $StatusLabel
            
            # Update UI
            Update-Results -LoginData $Global:LoginData -IPSummaryGrid $IPSummaryGrid -DetailGrid $DetailGrid -SummaryLabel $SummaryLabel
            
            $ExportButton.Enabled = $true
            $StatusLabel.Text = "Report generation completed successfully."
        } else {
            Add-DebugOutput "No events found in the specified time period"
            $StatusLabel.Text = "No events found for the specified user and time period."
            $SummaryLabel.Text = "No login events found."
        }
    }
    catch {
        $ErrorMsg = "An error occurred: $($_.Exception.Message)"
        Add-DebugOutput "ERROR: $ErrorMsg"
        [System.Windows.Forms.MessageBox]::Show($ErrorMsg, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        $StatusLabel.Text = "Error occurred during processing."
    }
    finally {
        # Re-enable controls and reset progress bar
        $SearchButton.Enabled = $true
        $UsernameTextBox.Enabled = $true
        $DaysNumeric.Enabled = $true
        
        # Reset progress bar to completed state briefly, then hide
        $ProgressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
        $ProgressBar.Value = 100
        [System.Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 500
        $ProgressBar.Value = 0
        [System.Windows.Forms.Application]::DoEvents()
    }
})

$ExportButton.Add_Click({
    Export-ToCSV -LoginData $Global:LoginData
})

# Initialize debug output
Add-DebugOutput "Application started successfully"
Add-DebugOutput "Ready to generate user login reports"

# Show the form
[System.Windows.Forms.Application]::Run($Form) 
