---
Name: osascript
Description: osascript is a native macOS binary that executes OSA language scripts - AppleScript and JavaScript. To execute, it is possible to pass a script file or pipe standard input. Scripts can be plain text or compiled scripts. An adversary may use osascript for c2 communication or post-exploitation objectives.
Author: Adam Nadrowski
Created: 2022-05-08
Full_Path:
  - Path: /usr/bin/osascript
Resources:
  - Link: https://objectivebythesea.org/v2/talks/OBTS_v2_Thomas.pdf
  - Link: https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5
  - Link: https://www.elastic.co/guide/en/security/current/prompt-for-credentials-with-osascript.html
Commands:

  - Name: osascript making network connections
    Description: This query detects any instance of osascript making a network connection. 
    Usecase: Adversaries may use this technique for C2 comms via HTTP or HTTPS. Due to osascript limitations, a valid certificate needs to be presented by the C2 server for successful HTTPS C2 comms.
    Category: Execution
    Privileges: User or Root
    MitreID: T1059.007
    Reproduce:
      - Prelude Operator: Run the "JXA Access" Chain, which contains the "Deploy a stage-0 JXA agent" TTP.
    Detect:
      - EDR: process_name = "osascript" AND netconn_count >= 1
    Respond:
      - Step: View the cmdline of osascript execution. This may provide helpful details about the src of execution.
      - Step: View the process' parent name and parent cmdline information.
      - Step: Check for any network connections, file writes, process creates of the osascript process and its parent.

  - Name: osascript executing JavaScript
    Description: This query will detect any instance of osascript executing JavaScript. 
    Usecase: Adversaries may use this for C2 comms. Apfell is a popular red team C2 agent that leverages this technique by default.
    Category: Execution
    Privileges: User or Root
    MitreID: T1059.007
    Reproduce:
      - Prelude Operator: Run the "JXA Access" Chain, which contains the "Deploy a stage-0 JXA agent" TTP.
    Detect:
      - EDR: process_name = "osascript" AND (process_cmdline = "*.js*" OR process_cmdline = "JavaScript")
    Respond:
      - Step: View the cmdline of osascript execution. This may provide helpful details about the src of execution.
      - Step: View the process' parent name and parent cmdline information.
      - Step: Check for any network connections, file writes, process creates of the osascript process and its parent.

  - Name: osascript prompting for password
    Description: This query is meant to detect credential access post-exploitation techniques. 
    Usecase: Adversaries may use this for post-exploitation objectives, such as credential access by generating a prompt to ask a user for their password.
    Category: Credential Access
    Privileges: User or Root
    MitreID: T1059.002
    Reproduce:
      - Prelude Operator: Run the "AppleScript - Prompt User for Password" TTP.
    Detect:
      - EDR: process_name = "osascript" and process_cmdline =  "*password*"
    Respond:
      - Step: View the cmdline of osascript execution. If a true positive, this may provide exactly what the attacker is attempting to achieve.
      - Step: View the process' parent information. Is the binary suspicious? Typically osascript post-exploitation execution's will be the result of an adversary "shelling out" from their C2.
      - Step: Does it make sense the parent process is asking the user for their password?

  - Name: osascript shelling out
    Description: This query will detect any instance of osascript running some binary, consistent with a C2 shelling out.
    Usecase: Adversaries may use this for post-exploitation objectives, such as credential access by generating a prompt to ask a user for their password.
    Category: Execution
    Privileges: User or Root
    MitreID: T1059
    Reproduce:
      - Prelude Operator: Run the "JXA Access" Chain, which contains the Deploy a stage-0 JXA agent TTP. Once the agent beacons back to Operator, select it and execute any macOS chain or TTP.
    Detect:
      - EDR: parent_process_name = "osascript"  AND NOT process_name = "osascript"
      - EDR Notes: When adding exclusions to this query for baselining or threat hunting, DO NOT exclude based on a shell/interpreter, such as sh or bash. When JXA agents are ran with osascript, they will shell out using sh, bash, or some other shell.
    Respond:
      - Step: View the cmdline of osascript execution. If a true positive, this may provide exactly what the attacker is attempting to achieve.
      - Step: View the cmdline of the target process. This will be the process launched by osascript. Is the cmdline suspicious? 

  - Name: osascript executing AppleScript
    Description: This query detect any instance of osascript executing AppleScript.
    Usecase: Adversaries may use this for post-exploitation objectives, such as credential access by generating a prompt to ask a user for their password.
    Category: Execution
    Privileges: User or Root
    MitreID: T1059.002
    Reproduce:
      - Prelude Operator: Run the "JXA Access" Chain, which contains the Deploy a stage-0 JXA agent TTP. Once the agent beacons back to Operator, select it and execute any macOS chain or TTP.
    Detect:
      - EDR: process_name = "osascript" AND NOT (process_cmdline = "*.js*" OR process_cmdline = "JavaScript")
      - EDR Notes: Notice we are making some dangerous exclusions - this is because we want to minimize duplicate alerts since the "osascript executing JavaScript" already covers this. This will generate lots of false positives, so you'll need to exclude based on process relationship information.
    Respond:
      - Step: View the cmdline of osascript execution. If a true positive, this may provide exactly what the attacker is attempting to achieve.
      - Step: View the process' parent information. Is the binary suspicious? Typically osascript post-exploitation execution's will be the result of an adversary "shelling out" from their C2.
---