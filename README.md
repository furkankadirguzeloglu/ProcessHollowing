# Process Hollowing - Code Injection Technique Simulation

This project simulates the **Process Hollowing** technique, which is commonly used to inject code into a legitimate process. The purpose of this project is to demonstrate how software can manipulate existing processes and execute unauthorized code without being detected by security mechanisms.

## Tested on:
- **Operating System**: Windows 11 24H2 x64
- **Operating System**: Windows 10 22H2 x64

## Dependencies:
- This project uses the [**libpeconv**](https://github.com/hasherezade/libpeconv) library for working with PE files and memory injections.

## Usage:
1. Clone the repository:
    ```bash
    git clone https://github.com/furkankadirguzeloglu/ProcessHollowing
    ```

2. Compile the code:
    - Follow the instructions specific to your environment to compile the code.

3. Run the program:
    The program requires two arguments:
    ```bash
    ProcessHollowing.exe <payloadPath> <targetPath>
    ```

    - **`<payloadPath>`**: The path to the payload (the code you want to inject).
    - **`<targetPath>`**: The path to the target process executable you want to inject the payload into.

    Example usage:
    ```bash
    ProcessHollowing.exe myfile.exe C:\Windows\System32\cmd.exe
    ```

4. Observe how the target process is modified and injected with code:
    - You can use debugging or monitoring tools to track the changes made to the target process.

## Disclaimer:
This project is for **educational purposes only**. It is important not to use this technique for any malicious activities. Ensure you are running this in a secure and isolated environment.

## Author:
[Furkan Kadir Güzeloğlu](https://github.com/furkankadirguzeloglu)

## Acknowledgements:
- Thanks to the community and research papers on **Process Hollowing** techniques.
- This project uses the [**libpeconv**](https://github.com/hasherezade/libpeconv) library to work with PE files and handle the injection.
- Inspired by various educational resources related to advanced software exploitation techniques.
  
## License:
This project is open source and distributed under the MIT License. See [LICENSE](https://github.com/furkankadirguzeloglu/ProcessHollowing/blob/main/LICENSE) for more information.
