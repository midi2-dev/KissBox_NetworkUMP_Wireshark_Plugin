-- midi2.lua
-- Lua plugin for Wireshark to decode Network UMP packets 
-- V0.3
-- 
-- Copyright (c) 2023 Benoit BOUCHEZ / KissBox
-- License : MIT
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.

-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
-- 
-- Release notes :
-- V0.1 : 
--  * first initial release based on V0.6 protocol specification
--
-- V0.2 - 10/11/2023
--  * Updated to V0.7 prototol version
--		* Removed unused code
--		* Removed flag informations in Ping messages
--		* Removed flag informations in Invitation messages
-- 		* Removed all "button pairing" related code
--
-- V0.3 - 14/12/2023
--	* Updated to V0.7.6 protocol specification
--  * Tree structure simplified to see directly type of packet instead of clicking twice
--  * Added first level of UMP packet decoder

midi2_protocol = Proto ("midi2", "Universal MIDI Protocol on Ethernet/WiFi")

midi_header = ProtoField.uint32("midi2_protocol.header", "Header", base.HEX)
cmd_code_field = ProtoField.uint8("midi2_protocol.command_code", "Command Code", base.HEX)
payload_len_field = ProtoField.uint8("midi2_protocol.payload_length", "Payload Length", base.DEC)
sequence_number_field = ProtoField.uint16 ("midi2_protocol.sequence_number", "Sequence Number", base.DEC)
command_specific_byte1_field = ProtoField.uint8("midi2_protocol.command_specific_byte1", base.DEC)
command_specific_byte2_field = ProtoField.uint8("midi2_protocol.command_specific_byte2", base.DEC)
ping_id_field = ProtoField.uint32("midi2_protocol.ping_id", base.DEC)
nak_reason_field = ProtoField.uint8("midi2_protocol.nak_reason", base.DEC)
ump_mt_field = ProtoField.uint8("midi2_protocol.mt", base.HEX)
ump_packet_field = ProtoField.uint8("midi2_protocol.message", base.DEC)
ump_channel_field = ProtoField.uint8("midi2_protocol.channel", base.DEC)

-- Create array starting at 0 to get number of bytes for each UMP Message Type
MTSize = {}
MTSize[0] = 1
MTSize[1] = 1
MTSize[2] = 1
MTSize[3] = 2
MTSize[4] = 2
MTSize[5] = 4
MTSize[6] = 1
MTSize[7] = 1
MTSize[8] = 2
MTSize[9] = 2
MTSize[10] = 2
MTSize[11] = 3
MTSize[12] = 3
MTSize[13] = 4
MTSize[14] = 4
MTSize[15] = 4

-- Decode packets with MT = 1 (System Common)
function decode_MT_1 (subtree, buffer, ByteCounter)
	local OP = buffer (ByteCounter+1, 1):uint()
	local PacketDetailTree
	
	if OP==0xF1 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI Time Code")
	elseif OP==0xF2 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Song Position Pointer")
	elseif OP==0xF3 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Song Select")
	elseif OP==0xF6 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Tune Request")
	elseif OP==0xF8 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Timing Clock")
	elseif OP==0xFA then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Start")
	elseif OP==0xFB then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Continue")
	elseif OP==0xFC then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Stop")
	elseif OP==0xFE then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Active Sensing")
	elseif OP==0xFF then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Reset")
	else
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Unknown System Common packet")
	end
end  -- decode_MT_1
-- ---------------------------------

-- Decode packets with MT = 2 (MIDI 1.0 Channel Voice)
function decode_MT_2 (subtree, buffer, ByteCounter)
	local Status = buffer (ByteCounter+1, 1):uint()
	local PacketDetailTree
	local Channel = buffer (ByteCounter+1, 1):uint()
	
	Status = bit32.band(Status, 0xF0)		-- Get status
	Channel = bit32.band(Channel, 0x0F)
	if Status==0x80 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Note Off")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0x90 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Note On")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0xA0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Poly Pressure")	
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0xB0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Control Change")	
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0xC0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Program Change")		
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0xD0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Channel Pressure")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0xE0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Pitch Bend")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	else
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Unknown MIDI 1.0 packet")
	end
end  -- decode_MT_2
-- ---------------------------------

-- Decode packets with MT = 4 (MIDI 2.0 Channel Voice)
function decode_MT_4 (subtree, buffer, ByteCounter)
	local Status = buffer (ByteCounter+1, 1):uint()
	local PacketDetailTree
	local Channel = buffer (ByteCounter+1, 1):uint()
	
	Status = bit32.band(Status, 0xF0)		-- Get status
	Channel = bit32.band(Channel, 0x0F)
	if Status==0x00 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Registered Per Note Controller")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0x10 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Assignable Per Note Controller")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0x20 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Registered Controller (RPN)")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0x30 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Assignable Controller (NRPN)")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0x40 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Relative Registered Controller")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0x50 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Relative Assignable Controller")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0x60 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Per-Note Pitch Bend")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0x80 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Note Off")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0x90 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Note On")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0xA0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Poly Pressure")	
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0xB0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Control Change")	
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0xC0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Program Change")		
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0xD0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Channel Pressure")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0xE0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Pitch Bend")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	elseif Status==0xF0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Per Note Management")
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
	else
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "Unknown MIDI 2.0 packet")
	end
end  -- decode_MT_4
-- ---------------------------------

-- Decode packets with MT = 0x0F (UMP Stream)
function decode_MT_F (subtree, buffer, ByteCounter)
	local Status = buffer (ByteCounter+1, 1):uint()
	local PacketDetailsTree
	
	if Status==0x00 then 
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 16), "Endpoint Discovery")
	elseif Status==0x01 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 16), "Endpoint Info Notification")
	elseif Status==0x02 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 16), "Device Identity Notification")	
	elseif Status==0x03 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 16), "Endpoint Name Notification")		
	elseif Status==0x04 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 16), "Product Instance ID Notification")	
	elseif Status==0x05 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 16), "Stream Configuration Request")	
	elseif Status==0x06 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 16), "Stream Configuration Notification")		
	elseif Status==0x10 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 16), "Function Block Discovery")	
	elseif Status==0x11 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 16), "Function Block Info Notification")	
	elseif Status==0x12 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 16), "Function Block Name Notification")	
	elseif Status==0x20 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 16), "Start of Clip")	
	elseif Status==0x21 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 16), "End of Clip")	
	else
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 16), "Unknown UMP Stream packet")
	end
end -- decode_MT_F
-- ---------------------------------

function decode_ump_command (subtree, buffer, ByteCounter, PayloadLength)
	local MT
	local UMPSize
	local PayloadCounter = 0;
	local PacketDetailTree
	local Status
	
	ByteCounter = ByteCounter+4
	
	-- Loop over all messages in the payload (a single UMP Data Command can contain multiple UMP messages)
	while (PayloadCounter<PayloadLength) do
		MT = buffer (ByteCounter, 1):uint()
		MT = bit32.rshift(MT, 4)
		UMPSize = MTSize[MT]	
		
		if MT==0x00 then
			-- Utility messages
			Status=buffer(ByteCounter, 1):uint()
			if (Status==0x00) then
				PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "NOOP")
			elseif (Status==0x01) then
				PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "JR Clock")
			elseif (Status==0x02) then
				PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "JR Timestamp")
			elseif (Status==0x03) then
				PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Delta Clockstamp Ticks Per Quarter Note")
			elseif (Status==0x04) then
				PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Delta Clockstamp")
			else
				PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Unknown utility message")
			end
		elseif MT==0x01 then
			-- System common messages
			decode_MT_1 (subtree, buffer, ByteCounter)
		elseif MT==0x02 then
			-- MIDI 1.0 Channel Voice messages
			decode_MT_2 (subtree, buffer, ByteCounter)
		elseif MT==0x03 then
			-- Data 64 bit messages
			PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "SYSEX 64 bit")
		elseif MT==0x04 then
			-- MIDI 2.0 Channel Voice messages
			decode_MT_4 (subtree, buffer, ByteCounter)
		elseif MT==0x05 then
			-- Data 128 bit messages
			PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 16), "SYSEX 128 bit")
		elseif MT==0x0F then
			decode_MT_F (subtree, buffer, ByteCounter)
		else
			PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, UMPSize*4), "Unknown UMP Packet")
		end
		
		PayloadCounter = PayloadCounter+UMPSize
		ByteCounter = ByteCounter+(UMPSize*4)
	end
end  -- decode_ump_command
-- ---------------------------------

function midi2_protocol.dissector (buffer, pinfo, tree)
	-- Check that packet we got from Wireshark is not empty
	length = buffer:len()
	if length == 0 then
		return
	end
	
	-- Put MIDI2 protocol name in "Protocol" column in Wireshark "live list"
	pinfo.cols.protocol = midi2_protocol.name
	
	-- Decode message in the detailed message pane
	local subtree = tree:add(midi2_protocol, buffer(), "Universal MIDI Protocol")
	
	-- Check that packet starts with MIDI signature
	local LHeader = buffer (0, 4):uint()
	
	if LHeader ~= 0x4D494449 then
		subtree:add ("Packet does not start with correct header")
		return
	end
	
	-- Parse the whole UDP packet
	local ByteCounter = 4		-- jump over header
	local PingID
	local SequenceCounter
	local subtree2
	local subtree3
	local ByeReason
	local CSD1
	
	while (ByteCounter<buffer:len()) do
	
		local CmdCode = buffer (ByteCounter, 1):uint()
		local PayloadLength = buffer (ByteCounter+1, 1):uint()
		local PayloadLengthBytes = PayloadLength*4			-- Convert Command Payload Length into bytes 	
		
		-- Interpret command header
		if CmdCode==0x01 then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Invitation")
			CSD1 = buffer (ByteCounter+2, 1):uint()
			--subtree3 = subtree2:add (endpoint_name_field, buffer(ByteCounter, 1), "Endpoint Name:")
			--subtree3:add (product_instance_id_field, buffer(ByteCounter, 1), "Product Instance ID:");
			-- TODO : add host endpoint name string
			-- TODO : add host product instance id string
		elseif CmdCode==0x02 then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Invitation with authentication")
			-- TODO : add Auth Digest hex field
		elseif CmdCode==0x03 then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Invitation with User authentication")
			-- TODO : add Auth Digest hex field
			-- TODO : add user name string
		elseif CmdCode==0x10 then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Invitation Reply: Accepted")
			--subtree3 = subtree2:add (endpoint_name_field, buffer(ByteCounter, 1), "Endpoint Name:")
			--subtree3:add (product_instance_id_field, buffer(ByteCounter, 1), "Product Instance ID:");			
			-- TODO : add host endpoint name
			-- TODO : add client product instance id string
		elseif CmdCode==0x11 then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Invitation Reply: Pending")
			-- TODO : add host endpoint name string
		elseif CmdCode==0x12 then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Invitation Reply: Authentication Required")
			-- TODO : add host endpoint name string
		elseif CmdCode==0x13 then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Invitation Reply: User Authentication Required")		
			-- TODO : add host endpoint name string
			
		elseif CmdCode==0x20 then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Ping")		
			PingID = buffer (ByteCounter+4, 4):uint()
			subtree3 = subtree2:add (ping_id_field, buffer(ByteCounter+4, 4), "Ping ID: " .. PingID)
			
		elseif CmdCode==0x21 then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Ping Reply")		
			PingID = buffer (ByteCounter+4, 4):uint()
			subtree3 = subtree2:add (ping_id_field, buffer(ByteCounter+4, 4), "Ping ID: " .. PingID)			
			
		elseif CmdCode==0x80 then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Retransmit")		
		elseif CmdCode==0x81 then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Retransmit Error")		
		elseif CmdCode==0x82 then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Report")		
		elseif CmdCode==0x8F then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "NAK")		
			NAKReason = buffer (ByteCounter+2, 1):uint()
			if NAKReason==1 then
				subtree3 = subtree2:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : Command not supported")
			elseif NAKReason==2 then
				subtree3 = subtree2:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : Command not expected")
			elseif NAKReason==3 then
				subtree3 = subtree2:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : Command malformed")
			elseif NAKReason==0x10 then
				subtree3 = subtree2:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : Session not active")
			elseif NAKReason==0x11 then
				subtree3 = subtree2:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : Authentication not accepted")
			elseif NAKReason==0x12 then
				subtree3 = subtree2:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : No pending invitation")
			elseif NAKReason==0x21 then
				subtree3 = subtree2:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : Bad Ping reply")
			elseif NAKReason==0x20 then
				subtree3 = subtree2:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : Missing UMP packets")
			else
				subtree3 = subtree2:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reserved NAK reason code")				
			-- TODO : add display of rejected command
			end
			
		elseif CmdCode==0xF0 then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Bye")		
			ByeReason = buffer (ByteCounter+2, 1):uint()
			-- TODO : add reason message if it exists in the packet
			if ByeReason==1 then 
				subtree3 = subtree2:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : User terminated session")	
			elseif ByeReason==2 then 
				subtree3 = subtree2:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Power Down")				
			elseif ByeReason==3 then 
				subtree3 = subtree2:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Too many missing UMP packets")				
			elseif ByeReason==4 then 
				subtree3 = subtree2:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Timeout / Too many missing PING responses")				
			elseif ByeReason==5 then 
				subtree3 = subtree2:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Session not active")				
			elseif ByeReason==0x40 then 
				subtree3 = subtree2:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Invitation failed / Too many opened sessions")							
			elseif ByeReason==0x42 then 
				subtree3 = subtree2:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Invitation failed / User did not accept session")
			elseif ByeReason==0x43 then 
				subtree3 = subtree2:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Invitation failed / Authentication failed")
			elseif ByeReason==0x44 then 
				subtree3 = subtree2:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Invitation failed / User name not found")
			elseif ByeReason==0x80 then 
				subtree3 = subtree2:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Invitation canceled")
			else
				subtree3 = subtree2:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reserved BYE reason code")
			end
			
		elseif CmdCode==0xF1 then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Bye Reply")		
			--subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Bye Reply")
			
		elseif CmdCode==0xFF then
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "UMP Packet")			
			SequenceCounter = buffer (ByteCounter+2, 2):uint()
			subtree3 = subtree2:add (sequence_number_field, buffer(ByteCounter+2, 2), "Sequence Number: " .. SequenceCounter)
			
			-- Display UMP messages from the payload
			decode_ump_command (subtree3, buffer, ByteCounter, PayloadLength)
			
		else
			-- Unknown command : display raw content
			subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Unknown command code")		
			subtree3 = subtree2:add (payload_len_field, buffer(ByteCounter+1, 1), "Payload length")		
		end

		-- Jump over Command Packet Header
		ByteCounter=ByteCounter+4		

		-- Go to next Command Packet
		ByteCounter=ByteCounter+PayloadLengthBytes
	end  -- while
end		-- midi2_protocol.dissector
-- ---------------------------------

-- Associate this dissector to port 5004 by default
local udp_port = DissectorTable.get("udp.port")
udp_port:add(5004, midi2_protocol)