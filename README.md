This plugin allows Wireshark to decode incoming Network UMP (Universal MIDI Packet) from a network adapter.

The plugin is based the V0.8.1 protocol preliminary specification 

### How to install the plugin
* Copy the the Lua file in the Wireshark installation directory, in the /plugin subfolder (on Windows machines, it is typically c:\Program Files\Wireshark\plugin)
* Start Wireshark
* Open Analyze / Enabled Protocols
* In the dialog that opens, check that MIDI2 protocol is visible. If not, it means that the Lua plugin has not been copied into the correct folder
* Verify that the MIDI2 checkbox is checked. If not, check it in order to enable protocol decoding
![Wireshark screenshot](Readme/MIDI2_Wireshark.PNG)
* Click on OK to close dialog

Plugin is now ready to use

### Possible conflict with Wireshark RTP-MIDI decoders
It can happen that the midi2 plugin and the rtpmidi plugin interact incorrectly, depending on the plugin order in Wireshark memory (typically if UDP port used for Network UMP is 5004, as rtpmidi plugin uses this port number by default too)

Two problematic situations can arise :
* an incoming RTP-MIDI session using port 5004 is being decoded by Network UMP plugin
* an incoming Network UMP stream using port 5004 is being decoded by RTP-MIDI session analyzer

In both cases, Wireshark will report "false" protocol errors, as the two protocols are totally different. It can also happen that some parts of the protocol are ignored by the analyzer (Wireshark then just displays the UDP payload, but does not interpret neither RTP-MIDI session nor Network UMP packets)

If such problems occur, the best solution is simply to deactivate the protocol not being used at the moment (in other terms, if you intend to analyze Network UMP protocol, just deactivate Apple MIDI and RTP-MIDI protocol analyzers).
This is done by unchecking the *applemidi* and *rtpmidi* checkboxes in Analyze / Enabled protocols.

If you need to work with RTP-MIDI again, just re-check *applemidi* and *rtpmidi*, and uncheck *midi2*.
