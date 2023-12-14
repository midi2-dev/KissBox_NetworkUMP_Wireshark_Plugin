-- midi2.lua
-- Lua plugin for Wireshark to decode Network UMP packets 
-- V0.2
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
-- V0.2 - 10/11/2023
--  * Updated to V0.7 prototol version
--		* Removed unused code
--		* Removed flag informations in Ping messages
--		* Removed flag informations in Invitation messages
-- 		* Removed all "button pairing" related code

midi2_protocol = Proto ("midi2", "Universal MIDI Protocol on Ethernet/WiFi")

midi_header = ProtoField.uint32("midi2_protocol.header", "Header", base.HEX)
cmd_code_field = ProtoField.uint8("midi2_protocol.command_code", "Command Code", base.HEX)
payload_len_field = ProtoField.uint8("midi2_protocol.payload_length", "Payload Length", base.DEC)
sequence_number_field = ProtoField.uint16 ("midi2_protocol.sequence_number", "Sequence Number", base.DEC)
command_specific_byte1_field = ProtoField.uint8("midi2_protocol.command_specific_byte1", base.DEC)
command_specific_byte2_field = ProtoField.uint8("midi2_protocol.command_specific_byte2", base.DEC)
ping_id_field = ProtoField.uint32("midi2_protocol.ping_id", base.DEC)
nak_reason_field = ProtoField.uint8("midi2_protocol.nak_reason", base.DEC)

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
	local PingID = 0
	local SequenceCounter = 0
	local Flags = 0
	local subtree2
	local subtree3
	local ByeReason = 0
	
	while (ByteCounter<buffer:len()) do
	
		local CmdCode = buffer (ByteCounter, 1):uint()
		local PayloadLength = buffer (ByteCounter+1, 1):uint()
		local PayloadLengthBytes = PayloadLength*4			-- Convert Command Payload Length into bytes 	
		
		subtree2 = subtree:add(midi2_protocol, buffer(ByteCounter, PayloadLengthBytes+4), "Command Packet")
		
		-- Interpret commands
		if CmdCode==0x01 then
			subtree3 = subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Invitation")
			Flags = buffer (ByteCounter+2, 1):uint()
			-- TODO : add host endpoint name string
			-- TODO : add host product instance id string
		elseif CmdCode==0x02 then
			subtree3 = subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Invitation with Authentication")
			-- TODO : add Auth Digest hex field
		elseif CmdCode==0x03 then
			subtree3 = subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Invitation with User Authentication")
			-- TODO : add Auth Digest hex field
			-- TODO : add user name string
		elseif CmdCode==0x10 then
			subtree3 = subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Invitation Reply: Accepted")
			-- TODO : add host endpoint name
			-- TODO : add client product instance id string
		elseif CmdCode==0x11 then
			subtree3 = subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Invitation Reply: Pending")
			-- TODO : add host endpoint name string
		elseif CmdCode==0x12 then
			subtree3 = subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Invitation Reply: Authentication Required")
			-- TODO : add host endpoint name string
		elseif CmdCode==0x13 then
			subtree3 = subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Invitation Reply: User Authentication Required")
			-- TODO : add host endpoint name string
			
		elseif CmdCode==0x20 then
			subtree3 = subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Ping");
			PingID = buffer (ByteCounter+4, 4):uint()
			subtree3:add (ping_id_field, buffer(ByteCounter+4, 4), "Ping ID: " .. PingID)
			
		elseif CmdCode==0x21 then
			subtree3 = subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Ping Reply");
			PingID = buffer (ByteCounter+4, 4):uint()
			subtree3:add (ping_id_field, buffer(ByteCounter+4, 4), "Ping ID: " .. PingID)			
			
		elseif CmdCode==0x80 then
			subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Retransmit")
		elseif CmdCode==0x81 then
			subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Retransmit Error")
		elseif CmdCode==0x82 then
			subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Report")
		elseif CmdCode==0x8F then
			subtree3 = subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "NAK")
			NAKReason = buffer (ByteCounter+2, 1):uint()
			if NAKReason==1 then
				subtree3:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : Command not supported")
			elseif NAKReason==2 then
				subtree3:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : Command not expected")
			elseif NAKReason==3 then
				subtree3:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : Command malformed")
			elseif NAKReason==0x10 then
				subtree3:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : Session not active")
			elseif NAKReason==0x11 then
				subtree3:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : Authentication not accepted")
			elseif NAKReason==0x12 then
				subtree3:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : No pending invitation")
			elseif NAKReason==0x21 then
				subtree3:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : Bad Ping reply")
			elseif NAKReason==0x20 then
				subtree3:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reason : Missing UMP packets")
			else
				subtree3:add (nak_reason_field, buffer(ByteCounter+2, 1), "Reserved NAK reason code")				
			-- TODO : add display of rejected command
			end
			
		elseif CmdCode==0xF0 then
			subtree3 = subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Bye")
			ByeReason = buffer (ByteCounter+2, 1):uint()
			-- TODO : add reason message if it exists in the packet
			if ByeReason==1 then 
				subtree3:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : User terminated session")	
			elseif ByeReason==2 then 
				subtree3:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Power Down")				
			elseif ByeReason==3 then 
				subtree3:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Too many missing UMP packets")				
			elseif ByeReason==4 then 
				subtree3:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Timeout / Too many missing PING responses")				
			elseif ByeReason==5 then 
				subtree3:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Session not active")				
			elseif ByeReason==0x40 then 
				subtree3:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Invitation failed / Too many opened sessions")							
			elseif ByeReason==0x42 then 
				subtree3:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Invitation failed / User did not accept session")
			elseif ByeReason==0x43 then 
				subtree3:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Invitation failed / Authentication failed")
			elseif ByeReason==0x44 then 
				subtree3:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Invitation failed / User name not found")
			elseif ByeReason==0x80 then 
				subtree3:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason : Invitation canceled")
			else
				subtree3:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reserved BYE reason code")
			end
			
		elseif CmdCode==0xF1 then
			subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Bye Reply")
			
		elseif CmdCode==0xFF then
			subtree3 = subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "UMP Packet")			
			SequenceCounter = buffer (ByteCounter+2, 2):uint()
			subtree3:add (sequence_number_field, buffer(ByteCounter+2, 2), "Sequence Number: " .. SequenceCounter)
			
		else
			-- Unknown command : display raw content
			subtree3 = subtree2:add (cmd_code_field, buffer(ByteCounter, 1), "Unknown command code")
			subtree3:add (payload_len_field, buffer(ByteCounter+1, 1), "Payload length")		
		end

		-- Jump over Command Packet Header
		ByteCounter=ByteCounter+4		

		-- Go to next Command Packet
		ByteCounter=ByteCounter+PayloadLengthBytes
	end
end		-- midi2_protocol.dissector
-- ---------------------------------

-- Associate this dissector to port 5004 by default
local udp_port = DissectorTable.get("udp.port")
udp_port:add(5004, midi2_protocol)