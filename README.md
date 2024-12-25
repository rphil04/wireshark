# wireshark
Wireshark scripts. Mostly lua

How to Run These Scripts

Save the Scripts:

Save the first script as general_creds.lua.
Save the second script as ics_creds.lua.

Locate Wireshark Plugin Directory:

Windows: C:\Users\<YourUser>\AppData\Roaming\Wireshark\plugins
Linux/macOS: ~/.local/lib/wireshark/plugins

Copy Scripts to Plugin Directory:

Place both .lua files into the appropriate directory.

Restart Wireshark:

Close and reopen Wireshark to load the scripts.

Capture and Analyze Traffic:

Start capturing traffic in your network.
Look for Cred-Detector or ICS-Creds in the protocol column in Wireshark.

Review Detected Credentials:

Expand the protocol tree in the packet details pane to see any detected credentials or anomalies.
