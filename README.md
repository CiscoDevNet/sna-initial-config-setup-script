This package contains the python script to capture the network settings to be sent to the 
Cisco Stealthwatch SMC server console.

# Dependencies:
To successfully execute this script, it requires [Python 3.9 version or higher](https://www.python.org/downloads/release/python-390/).
Script works with Stealthwatch version 7.3.0 or higher

Script is currently built to be executed on Mac, Windows and Linux operating systems.
It is recommended to run the script in a virtual environment. create virtual environment by running the following command
```
Use 
python -m venv envname # If there is only one version of python in the machine 
python3 -m venv envname # multiple python versions in machine and to choose python3 interpreter
python3.x -m venv envname # multiple python3 versions in machine and choose python3.x interpreter
```
Then based on the platform activate the venv by platform specific  command

| Platform      | Shell             | Command to activate virtual environment |
| ------------- | --------------  | --------------------------------------- |
| POSIX         | bash/zsh        |  $ source <venv>/bin/activate           |
|               | fish            |  $ source <venv>/bin/activate.fish      |
|               | csh/tcsh        |  $ source <venv>/bin/activate.csh       |
|               | PowerShell Core |  $ <venv>/bin/Activate.ps1              |
| Windows       | cmd.exe         |  C:\> <venv>\Scripts\activate.bat       |
|               | PowerShell      |  PS C:\> <venv>\Scripts\Activate.ps1    |

For more details on virtual environment please refer the official documentation [link](https://docs.python.org/3/library/venv.html)

For example :
In Mac/Linux
```
 python3 -m venv test
 source test/bin/activate
```
In Windows
```
 C:\> python3 -m venv test
 C:\> test\Scripts\activate.bat
```
To install the other dependencies, execute:
```
pip install -r requirements.txt
```
# Execution:

Script can be executed via OS terminals or IDE terminals(eg: Pycharm or vscode). 
The command to execute the script would be
```
python cisco_stealth_watch\stealthwatch_settings.py
```
####Warning: 
Since script relies on getpass python function when executed within IDLE you may get warning while entering 
password so its recommended running via OS terminal rather than via any IDLE



# Script details:

'cisco_stealth_watch' folder:
    stealthwatch_smcsettings.py: The main script which calls all the sub modules.
    'utils' folder:    
        get_ip_details.py: The script to capture the public ip, cidr range and nat gateway information.
        get_dns_dhcp.py: The script to collect the internal dns and dhcp server information.
        get_internal_network.py: The script to get the domain controller, email servers and critical range.
        misc.py: The script contains all common validation and utility functions
        smc_validator.py: The script to do a pydantic data validation on the collected data

# Output details:

Script generates three files
1. smc.settings file which has the collected network data.
2. smc.log file which has the log information of the execution.
3. .result file to record if the script data is already posted to smc server.
    if the .result file has a value of 1, that identifies the machine has already posted to smc.