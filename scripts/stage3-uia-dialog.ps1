param(
  [Parameter(Mandatory = $true)][string]$Title,
  [string]$Button = '',
  [switch]$Close,
  [int]$TimeoutSec = 90
)

# Drives NEXUS's own native Windows dialogs via UI Automation:
# waits for the dialog by caption, prints its visible text, then invokes the named button.
# This does not bypass any OS permission prompt; it clicks the application's own message box.
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -Namespace Stage3 -Name Win32 -MemberDefinition @'
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, System.UIntPtr dwExtraInfo);
'@
# Must match the dialog's physical-pixel coordinates before reading UIA bounds.
[Stage3.Win32]::SetProcessDPIAware() | Out-Null

$root = [System.Windows.Automation.AutomationElement]::RootElement
$deadline = (Get-Date).AddSeconds($TimeoutSec)
$win = $null

while ((Get-Date) -lt $deadline) {
  $cond = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::NameProperty, $Title)
  $win = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
  if ($win -ne $null) { break }
  Start-Sleep -Milliseconds 200
}

if ($win -eq $null) {
  [Console]::Error.WriteLine("dialog-not-found: $Title")
  exit 2
}

$all = $win.FindAll(
  [System.Windows.Automation.TreeScope]::Descendants,
  [System.Windows.Automation.Condition]::TrueCondition)
foreach ($e in $all) {
  try {
    if ($e.Current.Name) { Write-Output $e.Current.Name }
  } catch { }
}

if ($Close) {
  # Dismiss the dialog the way a user would (Esc / X): cancelId applies, so this is
  # always Deny for approvals and Reject for host keys. Use keystrokes instead of
  # WM_CLOSE because the Chromium task-dialog handle is not a normal Win32 window.
  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -Namespace Stage3 -Name Fg32 -MemberDefinition @'
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(System.IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(System.IntPtr hWnd, int nCmdShow);
'@
  $h = [System.IntPtr]$win.Current.NativeWindowHandle
  [Stage3.Fg32]::ShowWindow($h, 5) | Out-Null
  [Stage3.Fg32]::SetForegroundWindow($h) | Out-Null
  Start-Sleep -Milliseconds 300
  [System.Windows.Forms.SendKeys]::SendWait('{ESC}')
  exit 0
}

if (-not $Button) { [Console]::Error.WriteLine('button-required'); exit 3 }

$bcond = New-Object System.Windows.Automation.PropertyCondition(
  [System.Windows.Automation.AutomationElement]::NameProperty, $Button)
$btn = $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $bcond)
if ($btn -eq $null) {
  [Console]::Error.WriteLine("button-not-found: $Button")
  exit 3
}

$invoked = $false
try {
  $pattern = $btn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
  $pattern.Invoke()
  $invoked = $true
} catch { }

if (-not $invoked) {
  # Electron task-dialog buttons are custom CCPushButton panes with no UIA patterns.
  # Fall back to a real left-click at the button's centre.
  $r = $btn.Current.BoundingRectangle
  if ($r.Width -le 0 -or $r.Height -le 0) {
    [Console]::Error.WriteLine('button-has-no-bounds')
    exit 5
  }
  $x = [int]($r.X + ($r.Width / 2))
  $y = [int]($r.Y + ($r.Height / 2))
  [Stage3.Win32]::SetCursorPos($x, $y) | Out-Null
  Start-Sleep -Milliseconds 150
  [Stage3.Win32]::mouse_event(0x0002, 0, 0, 0, [System.UIntPtr]::Zero)
  [Stage3.Win32]::mouse_event(0x0004, 0, 0, 0, [System.UIntPtr]::Zero)
}
exit 0
