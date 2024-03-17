# Melody's Windows Post-Format Optimization Script

## Overview
This script is designed to accelerate the post-formatting process for Windows systems. It automates various optimization tasks inspired by the [Melody video](https://youtu.be/F_4BPuqn0_o?si=fORdG5zBgEY3799F), excluding service deactivation, which varies for each Windows version and must be done manually by the user.

## Recommendation
I recommend installing Windows without the internet to avoid creating a profile using a Microsoft account, and if possible, already having a video driver on a separate partition, as Windows Update will install an older version. After installation, you can connect to the network and wait for Windows Update to update whatever is necessary, so you can run the script without any problems

## Features
- Enables PowerShell unrestricted mode.
- Installs DirectX Graphic Tool.
- Disables Windows Update and related processes.
- Disables Windows Defender and related processes.
- Uninstall OneDrive.
- Allows the user to choose and install a browser (Thorium, Firefox Mercury, or Brave).
- Offers the option to install OpenShell and apply Melody's profile.
- Optimizes mouse and keyboard settings.
- Disables Security and Maintenance notifications.
- Adjusts Virtual Memory settings.
- Configures visual settings.
- Modifies various registry settings for performance enhancement.
- Apply the gpedit settings.
- Installs redistributables like Visual C++, DirectX, and .NET Frameworks.
- Sets firewall inbound settings.
- Grants permissions to system folders.
- Offers internet tweaks specific to Windows 10 or 11.
- Optimizes power plan settings.

## Usage
0. Disable defender before using this script.
1. Clone or download the zip file.
2. Run the script as an administrator inside the extracted folder.
3. Follow the on-screen instructions.
4. Reboot the system after the script finishes for changes to take effect.
5. On boot, a CMD prompt will appear to finalize the script, wait for it to finish and reboot again

## Usage in video
[video tutorial](https://youtu.be/fBckuUH2ITQ)

## Disclaimer
- Use this script at your own risk. Always ensure you have backups of important data before making system changes.
- The script may have different effects depending on your system configuration and version.

## Software credits
[abbodi1406](https://github.com/abbodi1406) from Visual C++ reddist software

[Fleex255](https://github.com/Fleex255) from PolicyPlus software

[Open-shell](https://github.com/Open-Shell) from Open-shell start menu

[M2Team](https://github.com/M2Team) from NanaRun

## Credits
This script is inspired by optimizations suggested in the [Melody video](https://youtu.be/F_4BPuqn0_o?si=fORdG5zBgEY3799F).

## License
This project is licensed under the [MIT License](https://opensource.org/licenses/MIT) - see the [LICENSE](https://github.com/Syrusaki/Melody-s-automated-script-from-video/blob/main/LICENSE.md) file for details.
