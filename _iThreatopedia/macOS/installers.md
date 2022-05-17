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

  - Name: macOS installer with preinstall script
    Description: This query detects any instance of macOS installers running a preinstall script.
    Usecase: Adversaries may pair this technique with a social engineering component to execute malware.
    Category: Execution
    Privileges: Root
    MitreID: T1204.002
    Behaviors:
      - Step: When executing the pkg file generated via iShelly, launchd runs Installer as user.
      - Step: After the user clicks through Installer prompts and authenticates, launchd runs package_script_service as root.
      - Step: package_script_service runs bash (or whatever script interpreter is used in the installer) as root with a cmdline similar to <pre><code>/bin/bash /tmp/PKInstallSandbox.YxqP12/Scripts/com.simple.test.ir2Zsb/preinstall /Users/user/iShelly/Payloads/install_pkg.pkg / / / </code></pre>
      - Step: The bash process launches cp as root with the following cmdline "cp files/operator-payload /Library/Application Support/ ". chmod is also executed to make it executable using cmdline "chmod +x /Library/Application Support/operator-payload "
      - Step: nohup then executes bash as root with cmdline "nohup bash -c /Library/Application\\ Support/operator-payload -name installer-w-preinstall-script"
      - Step: operator-payload executes as root using cmdline "/Library/Application Support/operator-payload -name installer-w-preinstall-script" and makes a network connection to operator.
    Execute:
      - Prelude Operator: Run <a href="https://github.com/AutomoxSecurity/iShelly">iShelly</a> with the "Installer Package w/ only preinstall script" Installer Package option. Then execute the pkg file, which will execute an Operator agent after clicking through Installer prompts.
    Detect:
      - EDR: parent_process_name = "package_script_service" and process_cmdline = "*preinstall*"
      - Notes: Alerting on this will be extremely noisy and is not recommended. If using for baselining, exclude based on the pkg name in process_cmdline, but beware an attacker can also leverage this by naming their package after a popular installer.
    Respond:
      - Step: View the process_cmdline field. This will contain the execution of the preinstall script and will have the name of the .pkg being executed.
      - Step: Look at children of the process (often this will be the bash process, but could be another script interpreter). These children will be the commands executed as a result of the preinstall script.
---
