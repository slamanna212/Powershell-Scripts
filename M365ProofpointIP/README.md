# M365 Proofpoint IP Transport Rule Manager

A PowerShell GUI application for creating Exchange Online transport rules to limit email reception to authorized Proofpoint IP addresses.

## Overview

This application helps you configure Exchange Online transport rules to block emails from unauthorized IP addresses while allowing emails from specific Proofpoint IP ranges. It provides a user-friendly graphical interface to manage the transport rule creation process.

## Features

- **Multi-screen GUI interface** with three main screens:
  1. **Authentication Screen**: Authenticate with Microsoft 365
  2. **Rule Status Screen**: Check existing transport rules and create new ones
  3. **Console Output Screen**: View detailed output from the rule creation process

- **Automated rule creation** with predefined Proofpoint IP ranges
- **Visual status indicators** (green/red lights) for rule existence
- **Detailed console output** for troubleshooting and confirmation
- **Error handling** with helpful error messages

## Prerequisites

### Required PowerShell Modules
- **ExchangeOnlineManagement** module
  ```powershell
  Install-Module -Name ExchangeOnlineManagement -Force
  ```

### Required Permissions
- **Exchange Administrator** role in Microsoft 365
- **Global Administrator** role (alternative)

### System Requirements
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- .NET Framework 4.7.2 or later

## Installation

1. **Download the application**:
   ```bash
   git clone <repository-url>
   cd M365ProofpointIP
   ```

2. **Install required PowerShell module**:
   ```powershell
   Install-Module -Name ExchangeOnlineManagement -Force
   ```

3. **Run as Administrator** (recommended):
   - Right-click on PowerShell
   - Select "Run as Administrator"

## Usage

### Starting the Application

#### Method 1: Direct PowerShell Execution
```powershell
.\M365ProofpointIP-GUI.ps1
```

#### Method 2: Using the Batch File (if created)
```cmd
run-app.bat
```

### Application Workflow

#### Screen 1: Authentication
1. **Title**: "Limit Email Reception to Proofpoint IPs"
2. **Action**: Click "Authenticate with Microsoft 365"
3. **Process**: 
   - Checks for ExchangeOnlineManagement module
   - Prompts for Microsoft 365 credentials
   - Establishes connection to Exchange Online

#### Screen 2: Rule Status Check
1. **Rule Check**: Automatically checks for existing "Block Messages from Unauthorized IPs" rule
2. **Status Indicators**:
   - 🟢 **Green Light**: Rule exists (no action needed)
   - 🔴 **Red Light**: Rule not found (action required)
3. **Actions**:
   - Click "Add Transport Rule" to create the rule
   - Click "Back" to return to authentication screen

#### Screen 3: Console Output
1. **Real-time output** showing rule creation progress
2. **Detailed information** about:
   - Rule parameters
   - IP ranges being configured
   - Success/error messages
   - Rule properties after creation

## Transport Rule Details

### Rule Name
`Block Messages from Unauthorized IPs`

### Rule Configuration
- **Priority**: 0 (highest priority)
- **Action**: Reject messages with "5.7.1 Unauthorized IP" error
- **Exceptions**: 
  - Messages from authorized Proofpoint IP ranges
  - Meeting forward messages (Exchange internal)

### Proofpoint IP Ranges (43 total)
The rule allows emails from these IP ranges:
- 67.231.144.0/24 through 67.231.156.0/24 (13 ranges)
- 148.163.128.0/24 through 148.163.159.0/24 (32 ranges)

### PowerShell Command Executed
```powershell
New-TransportRule -Name "Block Messages from Unauthorized IPs" `
  -Priority 0 `
  -ExceptIfSenderIpRanges @('67.231.149.0/24', '67.231.152.0/24', ...) `
  -ExceptIfHeaderContainsMessageHeader 'X-MS-Exchange-MeetingForward-Message' `
  -ExceptIfHeaderContainsWords 'Forward' `
  -RejectMessageReasonText "Unauthorized IP" `
  -RejectMessageEnhancedStatusCode "5.7.1"
```

## Troubleshooting

### Common Issues

#### Authentication Failures
- **Cause**: Insufficient permissions or expired credentials
- **Solution**: Ensure you have Exchange Administrator role and valid credentials

#### Module Not Found Error
- **Cause**: ExchangeOnlineManagement module not installed
- **Solution**: 
  ```powershell
  Install-Module -Name ExchangeOnlineManagement -Force
  ```

#### Rule Creation Errors
- **Cause**: Rule already exists or insufficient permissions
- **Solutions**:
  - Check if rule already exists in Exchange Admin Center
  - Verify Exchange Administrator permissions
  - Ensure PowerShell execution policy allows script execution

#### Permission Errors
- **Cause**: Not running as Administrator
- **Solution**: Run PowerShell as Administrator

### Execution Policy Issues
If you encounter execution policy errors:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Security Considerations

- **Run as Administrator**: Recommended for Exchange operations
- **Secure Authentication**: Uses Microsoft's secure authentication flow
- **Audit Trail**: All actions are logged in Exchange Online audit logs
- **Principle of Least Privilege**: Only requires Exchange Administrator role

## Support

### Viewing Created Rules
After creation, you can view the rule in:
- **Exchange Admin Center**: Mail flow > Rules
- **PowerShell**: `Get-TransportRule -Identity "Block Messages from Unauthorized IPs"`

### Modifying Rules
To modify the rule after creation:
```powershell
Set-TransportRule -Identity "Block Messages from Unauthorized IPs" -Parameter Value
```

### Removing Rules
To remove the rule:
```powershell
Remove-TransportRule -Identity "Block Messages from Unauthorized IPs" -Confirm:$false
```

## License

This application is provided as-is for educational and administrative purposes.

## Contributing

Feel free to submit issues and enhancement requests! 