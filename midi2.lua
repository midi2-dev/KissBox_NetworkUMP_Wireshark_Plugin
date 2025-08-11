-- midi2.lua
-- Lua plugin for Wireshark to decode Network UMP packets 
-- V0.5
-- 
-- Developed by Benoit BOUCHEZ (KissBox) and Pete BROWN (Microsoft)
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
--
-- V0.4 - 24/12/2024
--  * Updated to V0.8.1 protocol specification
--  * Inclusion of changes made by Pete Brown (Microsoft)
--
-- V0.5 - 27/12/2024
--  * All references to bit32 removed as latest Wireshark version (4.4.2) uses Lua 5.4 (bit32 library removed since Lua 5.3)
--  * Enhanced UMP decoding (display of Group, Channel, Note Number, etc...)

midi2_protocol = Proto ("midi2", "User Datagram Protocol for Universal MIDI Packets")

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
ump_group_field = ProtoField.uint8("midi2_protocol.group", base.DEC)
ump_channel_field = ProtoField.uint8("midi2_protocol.channel", base.DEC)
ump_midi_byte1_field = ProtoField.uint8("midi2_protocol.byte1", base.DEC)
ump_midi_byte2_field = ProtoField.uint8("midi2_protocol.byte2", base.DEC)
ump_midi_data32_field = ProtoField.uint32("midi2_protocol.data32", base.DEC)
ump_midi2_note_velocity_field = ProtoField.uint16("midi2_protocol.midi2_note_velocity", base.DEC)
ump_midi2_note_attribute_field = ProtoField.uint16("midi2_protocol.midi2_note_attribute", base.DEC)
authentication_state_field = ProtoField.uint8("midi2_protocol.authentication_state", base.HEX)

ump_endpoint_name_field = ProtoField.new("UMP Endpoint Name", "midi2_protocol.ump_endpoint_name", ftypes.STRING)
product_instance_id_field = ProtoField.new("Product Instance Id", "midi2_protocol.product_instance_id", ftypes.STRING)
crypto_nonce_field = ProtoField.new("CryptoNonce", "midi2_protocol.crypto_nonce", ftypes.BYTES)

midi2_protocol.fields = { ump_endpoint_name_field, product_instance_id_field, crypto_nonce_field }

-- Define constants for Network UMP (re
INVITATION_COMMAND_CODE				 	 				= 0x01
INVITATION_AUTHENTICATE_COMMAND_CODE 					= 0x02
INVITATION_USER_AUTHENTICATE_COMMAND_CODE				= 0x03
INVITATION_ACCEPTED_COMMAND_CODE						= 0x10
INVITATION_PENDING_COMMAND_CODE							= 0x11
INVITATION_AUTHENTICATION_REQUIRED_COMMAND_CODE			= 0x12
INVITATION_USER_AUTHENTICATION_REQUIRED_COMMAND_CODE	= 0x13
PING_COMMAND_CODE										= 0x20
PING_REPLY_COMMAND_CODE									= 0x21
RETRANSMIT_COMMAND_CODE									= 0x80
RETRANSMIT_ERROR_COMMAND_CODE							= 0x81
SESSION_RESET_COMMAND_CODE								= 0x82
SESSION_RESET_REPLY_COMMAND_CODE						= 0x83
NAK_COMMAND_CODE										= 0x8F
BYE_COMMAND_CODE										= 0xF0
BYE_REPLY_COMMAND_CODE									= 0xF1
UMP_DATA_COMMAND_CODE									= 0xFF

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

-- Return command code name in human readable format
function get_command_code_display_text (Code)
	local text;
	
	if Code==0xFF then text = "UMP"
	elseif Code==0x01 then text = "Invitation"
	elseif Code==0x02 then text = "Invitation with Authentication"
	elseif Code==0x03 then text = "Invitation with User Authentication"
	elseif Code==0x10 then text = "Invitation Reply: Accepted"
	elseif Code==0x11 then text = "Invitation Reply: Pending"
	elseif Code==0x12 then text = "Invitation Reply: Authentication Required"
	elseif Code==0x13 then text = "Invitation Reply: User Authentication Required"
	elseif Code==0x20 then text = "Ping"
	elseif Code==0x21 then text = "Ping Reply"
	elseif Code==0x80 then text = "Retransmit Request"
	elseif Code==0x81 then text = "Retransmit Error"
	elseif Code==0x82 then text = "Session Reset"
	elseif Code==0x83 then text = "Session Reset Reply"
	elseif Code==0x8F then text = "NAK"
	elseif Code==0xF0 then text = "Bye"
	elseif Code==0xF1 then text = "Bye Reply"
	else text = "Unknown command"
	end
	
	return text
end -- get_command_code_display_text
-- ---------------------------------

function get_bye_reason_display_text (Code)
	local text;
	
    if Code==0x00 then text = "Reserved"
    elseif Code==0x01 then text = "User terminated session"
    elseif Code==0x02 then text = "Power Down"
    elseif Code==0x03 then text = "Too many missing UMP packets"	
    elseif Code==0x04 then text = "Timeout / Too many missing PING responses"
    elseif Code==0x05 then text = "Session not established"
    elseif Code==0x06 then text = "No pending session"
    elseif Code==0x07 then text = "Protocol Error"
    elseif Code==0x40 then text = "Invitation Failed: Too many opened sessions"
    elseif Code==0x41 then text = "Invitation with Authentication Rejected: Missing prior invitation attempt without authentication"
    elseif Code==0x42 then text = "Invitation Rejected: User did not accept session"
    elseif Code==0x43 then text = "Invitation Rejected: Authentication failed"
    elseif Code==0x44 then text = "Invitation Rejected: User name not found"
    elseif Code==0x45 then text = "No matching authentication method"
    elseif Code==0x80 then text = "Invitation canceled"
    else text = "Unknown reason"
    end
	
	return text
end -- get_bye_reason_display_text
-- ---------------------------------

function get_nak_code_display_text (Code)
	local text;
	
	if Code==1 then text = "Command not supported"
	elseif Code==2 then text = "Command not expected"
	elseif Code==3 then text = "Command malformed"
	elseif Code==0x20 then text = "Bad PING reply"
	else text = "Reserved NAK reason code"
	end
	
	return text
end  -- get_nak_code_reason_text
-- ---------------------------------

function get_auth_state_display_text(Code)
    local text

    if Code==0 then text = "First authentication request"
    elseif Code==1 then text = "Previously provided Authentication Digest is not correct"
    else text = "Reserved authentication state code"
    end

    return text
end  -- get_auth_state_display_text
-- ---------------------------------

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
	local PacketDetailTree
	local Group = buffer (ByteCounter, 1):uint()
	local Status = buffer (ByteCounter+1, 1):uint()
	local Channel = buffer (ByteCounter+1, 1):uint()
	local DataByte1 = buffer (ByteCounter+2, 1):uint()
	local DataByte2 = buffer (ByteCounter+3, 1):uint()
	
	-- bit32 library has been removed from Lua 5.3
	--Status = bit32.band(Status, 0xF0)
	--Channel = bit32.band(Channel, 0x0F)
	--Group = bit32.band(Group, 0x0F)

	Status = Status & 0xF0
	Channel = Channel & 0x0F
	Group = Group & 0x0F
	DataByte1 = DataByte1 & 0x7F
	DataByte2 = DataByte2 & 0x7F
	
	if Status==0x80 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Note Off")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Note:" .. DataByte1)
		PacketDetailTree:add (ump_midi_byte2_field, buffer(ByteCounter+3, 1), "Velocity:" .. DataByte2)
	elseif Status==0x90 then
		if DataByte2 == 0 then
			PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Note Off")
			PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
			PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
			PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Note:" .. DataByte1)
		else
			PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Note On")
			PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
			PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
			PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Note:" .. DataByte1)
			PacketDetailTree:add (ump_midi_byte2_field, buffer(ByteCounter+3, 1), "Velocity:" .. DataByte2)
		end
	elseif Status==0xA0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Poly Pressure")	
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Note:" .. DataByte1)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+3, 1), "Pressure:" .. DataByte2)		
	elseif Status==0xB0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Control Change")	
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Control:" .. DataByte1)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+3, 1), "Value:" .. DataByte2)		
	elseif Status==0xC0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Program Change")		
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Program:" .. DataByte1)
	elseif Status==0xD0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Channel Pressure")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Pressure:" .. DataByte1)		
	elseif Status==0xE0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "MIDI 1.0 Pitch Bend")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PackatDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 2), "PitchBend:" .. (DataByte2*128)+DataByte1)
	else
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 4), "Unknown MIDI 1.0 packet")
	end
end  -- decode_MT_2
-- ---------------------------------

-- Decode packets with MT = 4 (MIDI 2.0 Channel Voice message)
function decode_MT_4 (subtree, buffer, ByteCounter)
	local Status = buffer (ByteCounter+1, 1):uint()
	local PacketDetailTree
	local Channel = buffer (ByteCounter+1, 1):uint()
	local Group = buffer (ByteCounter, 1):uint()
	local DataByte1 = buffer (ByteCounter+2, 1):uint()
	local DataByte2 = buffer (ByteCounter+3, 1):uint()
	local MIDI2Data = buffer (ByteCounter+4, 4):uint()
	local NoteVelocity = buffer (ByteCounter+4, 2):uint()
	local NoteAttribute = buffer (ByteCounter+6, 2):uint()
	
	-- bit32 library has been removed from Lua 5.3
	--Status = bit32.band(Status, 0xF0)
	--Channel = bit32.band(Channel, 0x0F)
	--Group = bit32.band(Group, 0x0F)
	
	Status = Status & 0xF0
	Channel = Channel & 0x0F
	Group = Group & 0x0F
		
	if Status==0x00 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Registered Per Note Controller")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Note:" .. DataByte1)
		PacketDetailTree:add (ump_midi_byte2_field, buffer(ByteCounter+3, 1), "Index:" .. DataByte2)
		PacketDetailTree:add (ump_midi_data32_field, buffer(ByteCounter+4, 4), "Value:" .. MIDI2Data)	
		
	elseif Status==0x10 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Assignable Per Note Controller")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Note:" .. DataByte1)
		PacketDetailTree:add (ump_midi_byte2_field, buffer(ByteCounter+3, 1), "Index:" .. DataByte2)
		PacketDetailTree:add (ump_midi_data32_field, buffer(ByteCounter+4, 4), "Value:" .. MIDI2Data)	
		
	elseif Status==0x20 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Registered Controller (RPN)")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Bank:" .. DataByte1)
		PacketDetailTree:add (ump_midi_byte2_field, buffer(ByteCounter+3, 1), "Index:" .. DataByte2)
		PacketDetailTree:add (ump_midi_data32_field, buffer(ByteCounter+4, 4), "Value:" .. MIDI2Data)		
		
	elseif Status==0x30 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Assignable Controller (NRPN)")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Bank:" .. DataByte1)
		PacketDetailTree:add (ump_midi_byte2_field, buffer(ByteCounter+3, 1), "Index:" .. DataByte2)
		PacketDetailTree:add (ump_midi_data32_field, buffer(ByteCounter+4, 4), "Value:" .. MIDI2Data)		
		
	elseif Status==0x40 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Relative Registered Controller")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Bank:" .. DataByte1)
		PacketDetailTree:add (ump_midi_byte2_field, buffer(ByteCounter+3, 1), "Index:" .. DataByte2)
		PacketDetailTree:add (ump_midi_data32_field, buffer(ByteCounter+4, 4), "Value:" .. MIDI2Data)	
		
	elseif Status==0x50 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Relative Assignable Controller")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Bank:" .. DataByte1)
		PacketDetailTree:add (ump_midi_byte2_field, buffer(ByteCounter+3, 1), "Index:" .. DataByte2)
		PacketDetailTree:add (ump_midi_data32_field, buffer(ByteCounter+4, 4), "Value:" .. MIDI2Data)	
		
	elseif Status==0x60 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Per-Note Pitch Bend")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Note:" .. DataByte1)
		PacketDetailTree:add (ump_midi_data32_field, buffer(ByteCounter+4, 4), "Value:" .. MIDI2Data)
		
	elseif Status==0x80 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Note Off")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Note:" .. DataByte1)
		PacketDetailTree:add (ump_midi_byte2_field, buffer(ByteCounter+3, 1), "Attribute Type:" .. DataByte2)
		PacketDetailTree:add (ump_midi2_note_velocity_field, buffer(ByteCounter+4, 2), "Velocity:" .. NoteVelocity)
		PacketDetailTree:add (ump_midi2_note_attribute_field, buffer(ByteCounter+6, 2), "Attribute:" .. NoteAttribute)

	elseif Status==0x90 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Note On")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Note:" .. DataByte1)
		PacketDetailTree:add (ump_midi_byte2_field, buffer(ByteCounter+3, 1), "Attribute Type:" .. DataByte2)
		PacketDetailTree:add (ump_midi2_note_velocity_field, buffer(ByteCounter+4, 2), "Velocity:" .. NoteVelocity)
		PacketDetailTree:add (ump_midi2_note_attribute_field, buffer(ByteCounter+6, 2), "Attribute:" .. NoteAttribute)

	elseif Status==0xA0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Poly Pressure")	
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Note:" .. DataByte1)
		PacketDetailTree:add (ump_midi_data32_field, buffer(ByteCounter+4, 4), "Pressure:" .. MIDI2Data)

	elseif Status==0xB0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Control Change")	
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Control:" .. DataByte1)
		PacketDetailTree:add (ump_midi_data32_field, buffer(ByteCounter+4, 4), "Value:" .. MIDI2Data)
		
	elseif Status==0xC0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Program Change")		
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		if ((DataByte2&0x01) == 0x01) then
			PacketDetailTree:add (ump_midi_data32_field, buffer(ByteCounter+4, 4), "Bank MSB:" .. (MIDI2Data>>8)&0x7F)	
			PacketDetailTree:add (ump_midi_data32_field, buffer(ByteCounter+4, 4), "Bank LSB:" .. MIDI2Data&0x7F)				
		end
		PacketDetailTree:add (ump_midi_data32_field, buffer(ByteCounter+4, 4), "Program:" .. MIDI2Data>>24)		
		
	elseif Status==0xD0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Channel Pressure")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_data32_field, buffer(ByteCounter+4, 4), "Pressure:" .. MIDI2Data)
		
	elseif Status==0xE0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Pitch Bend")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_data32_field, buffer(ByteCounter+4, 4), "Value:" .. MIDI2Data)
		
	elseif Status==0xF0 then
		PacketDetailTree = subtree:add(ump_packet_field, buffer(ByteCounter, 8), "MIDI 2.0 Per Note Management")
		PacketDetailTree:add (ump_group_field, buffer(ByteCounter, 1), "Group:" .. Group)
		PacketDetailTree:add (ump_channel_field, buffer(ByteCounter+1, 1), "Channel:" .. Channel)
		PacketDetailTree:add (ump_midi_byte1_field, buffer(ByteCounter+2, 1), "Note:" .. DataByte1)
		PacketDetailTree:add (ump_midi_byte2_field, buffer(ByteCounter+3, 1), "Options:" .. DataByte2)
		
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
	local MT = 0
	local UMPSize
	local PayloadCounter = 0;
	local PacketDetailTree
	local Status
	
	ByteCounter = ByteCounter+4
	
	-- Loop over all messages in the payload (a single UMP Data Command can contain multiple UMP messages)
	while (PayloadCounter<PayloadLength) do
		MT = buffer (ByteCounter, 1):uint()
		
		-- bit32 library has been removed from Lua 5.3
		--MT = bit32.rshift(MT, 4)
		MT = MT >> 4
		
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
    -- 32 bit udp header followed by 32 bit command packet header
    -- 8 bytes minimum size	length = buffer:len()
	local length = buffer:len()
    if length < 8 then
		return 0
	end
	
	-- Check that packet starts with MIDI signature
	local LHeader = buffer (0, 4):uint()
	
	if LHeader ~= 0x4D494449 then
		subtree:add ("Packet does not start with correct header")
		return 0
	end	
	
	-- Put MIDI2 protocol name in "Protocol" column in Wireshark "live list"
	pinfo.cols.protocol = midi2_protocol.name
	
	-- Decode message in the detailed message pane
	local subtree = tree:add(midi2_protocol, buffer(), "Universal MIDI Protocol")
	
	-- Parse the whole UDP packet
	local ByteCounter = 4		-- jump over header
	local PingID = 0
	local SequenceCounter = 0
	local subtree2
	local subtree3
	local ByeReason = 0
	local commandCount = 0
	local CommandHeaderSizeBytes = 4            -- constant value
    local infoColumnText = ""
	
	while (ByteCounter<buffer:len()) do
	    -- keep track of the number of MIDI command packets in this UDP packet
        commandCount = commandCount + 1
	
		local CmdCode = buffer (ByteCounter, 1):uint()
		local PayloadLengthWords = buffer (ByteCounter + 1, 1):uint()
		local PayloadLengthBytes = PayloadLengthWords * 4			-- Convert Command Payload Length into bytes
		
		local commandCodeName = get_command_code_display_text(CmdCode)
        subtree2 = subtree:add(midi2_protocol, buffer:range(ByteCounter, 1), "Command Packet " .. CmdCode .. " : " .. commandCodeName)
		subtree3 = subtree2:add (payload_len_field, buffer:range(ByteCounter+1, 1), "Payload length in 32-bit words: " .. PayloadLengthWords)
		
		-- Interpret command header
		if CmdCode==INVITATION_COMMAND_CODE	then
            local umpEndpointNameLengthInWords = buffer (ByteCounter+2, 1):uint()
    		subtree3:add (command_specific_byte1_field, buffer:range(ByteCounter+2, 1), "UMP Endpoint Name Length in 32-bit words: " .. umpEndpointNameLengthInWords)

            local Flags = buffer (ByteCounter+3, 1):uint()
			-- bit32 library has been removed from Lua 5.3
			--if (bit32.band(Flags, 0x01) == 0x01) then
			if ((Flags & 0x01) == 0x01) then
				subtree3:add (command_specific_byte2_field, buffer:range(ByteCounter+3, 1), "Flag: Client supports sending Invitation with Authentication")
			end

			--if (bit32.band(Flags, 0x02) == 0x02) then
			if ((Flags & 0x02) == 0x02) then
				subtree3:add (command_specific_byte2_field, buffer:range(ByteCounter+3, 1), "Flag: Client supports sending Invitation with User Authentication")
			end

            local umpEndpointNameStartByte = ByteCounter + CommandHeaderSizeBytes
            local umpEndpointNameByteCount = umpEndpointNameLengthInWords * 4
            subtree3:add_packet_field(ump_endpoint_name_field, buffer:range(umpEndpointNameStartByte, umpEndpointNameByteCount), ENC_UTF_8)
            
            local productInstanceIdStartByte = umpEndpointNameStartByte + umpEndpointNameByteCount
            local productInstanceIdByteCount = PayloadLengthBytes - umpEndpointNameByteCount
            subtree3:add_packet_field(product_instance_id_field, buffer:range(productInstanceIdStartByte, productInstanceIdByteCount), ENC_ASCII)
		
            infoColumnText = commandCodeName .. " from " .. buffer(umpEndpointNameStartByte, umpEndpointNameByteCount):string(ENC_UTF_8)

		elseif CmdCode==INVITATION_AUTHENTICATE_COMMAND_CODE then
			-- TODO : add flags and endpoint name
            infoColumnText = commandCodeName .. " from "
			
		elseif CmdCode==INVITATION_USER_AUTHENTICATE_COMMAND_CODE then
			-- TODO : add flags and endpoint name
            infoColumnText = commandCodeName .. " from "
			
		elseif CmdCode==INVITATION_ACCEPTED_COMMAND_CODE then
            local umpEndpointNameLengthInWords = buffer (ByteCounter+2, 1):uint()
    		subtree3:add (command_specific_byte1_field, buffer:range(ByteCounter+2, 1), "UMP Endpoint Name Length in 32-bit words: " .. umpEndpointNameLengthInWords)

            local umpEndpointNameStartByte = ByteCounter + CommandHeaderSizeBytes
            local umpEndpointNameByteCount = umpEndpointNameLengthInWords * 4
            subtree3:add_packet_field(ump_endpoint_name_field, buffer:range(umpEndpointNameStartByte, umpEndpointNameByteCount), ENC_UTF_8)
            
            local productInstanceIdStartByte = umpEndpointNameStartByte + umpEndpointNameByteCount
            local productInstanceIdByteCount = PayloadLengthBytes - umpEndpointNameByteCount
            subtree3:add_packet_field(product_instance_id_field, buffer:range(productInstanceIdStartByte, productInstanceIdByteCount), ENC_ASCII)
			
            infoColumnText = commandCodeName .. " from " .. buffer(umpEndpointNameStartByte, umpEndpointNameByteCount):string(ENC_UTF_8)
			
		elseif CmdCode==INVITATION_PENDING_COMMAND_CODE then
            infoColumnText = commandCodeName .. " from "
			
		elseif CmdCode==INVITATION_AUTHENTICATION_REQUIRED_COMMAND_CODE then
            local umpEndpointNameLengthInWords = buffer (ByteCounter+2, 1):uint()
    		subtree3:add (command_specific_byte1_field, buffer:range(ByteCounter+2, 1), "UMP Endpoint Name Length in 32-bit words: " .. umpEndpointNameLengthInWords)

            local authenticationState = buffer(ByteCounter+3, 1):uint()
            subtree3:add(authentication_state_field, buffer:range(ByteCounter+3, 1), "Authentication state: " .. get_auth_state_display_text(authenticationState))

            local cryptoNonceStartByte = ByteCounter + CommandHeaderSizeBytes
            local cryptoNonceByteCount = 16
            subtree3:add_packet_field(crypto_nonce_field, buffer:range(cryptoNonceStartByte, cryptoNonceByteCount), ENC_ASCII)

            local umpEndpointNameStartByte = cryptoNonceStartByte + cryptoNonceByteCount
            local umpEndpointNameByteCount = umpEndpointNameLengthInWords * 4
            subtree3:add_packet_field(ump_endpoint_name_field, buffer:range(umpEndpointNameStartByte, umpEndpointNameByteCount), ENC_UTF_8)
            
            local productInstanceIdStartByte = umpEndpointNameStartByte + umpEndpointNameByteCount
            local productInstanceIdByteCount = PayloadLengthBytes - umpEndpointNameByteCount - cryptoNonceByteCount
            subtree3:add_packet_field(product_instance_id_field, buffer:range(productInstanceIdStartByte, productInstanceIdByteCount), ENC_ASCII)

            infoColumnText = commandCodeName .. " from " .. buffer(umpEndpointNameStartByte, umpEndpointNameByteCount):string(ENC_UTF_8)
			
		elseif CmdCode==INVITATION_USER_AUTHENTICATION_REQUIRED_COMMAND_CODE then
            infoColumnText = commandCodeName
			
		elseif CmdCode==PING_COMMAND_CODE then
			PingID = buffer (ByteCounter + 4, 4):uint()
			subtree3:add (ping_id_field, buffer(ByteCounter+4, 4), "Ping ID: " .. PingID)
			
            infoColumnText = commandCodeName .. " " .. PingID
			
		elseif CmdCode==PING_REPLY_COMMAND_CODE then
			PingID = buffer (ByteCounter+4, 4):uint()
			subtree3:add (ping_id_field, buffer(ByteCounter+4, 4), "Ping ID: " .. PingID)			

            infoColumnText = commandCodeName .. " " .. PingID		
			
		elseif CmdCode==RETRANSMIT_COMMAND_CODE then
            infoColumnText = commandCodeName
			
		elseif CmdCode==RETRANSMIT_ERROR_COMMAND_CODE then
            infoColumnText = commandCodeName
			
		elseif CmdCode==SESSION_RESET_COMMAND_CODE then
            infoColumnText = commandCodeName
			
		elseif CmdCode==SESSION_RESET_REPLY_COMMAND_CODE then
            infoColumnText = commandCodeName
			
		elseif CmdCode==NAK_COMMAND_CODE then
			NAKReason = buffer (ByteCounter+2, 1):uint()			
            subtree3:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason:" .. get_nak_code_display_text(NAKReason))
		
            infoColumnText = commandCodeName
						
		elseif CmdCode==BYE_COMMAND_CODE then
            ByeReason = buffer (ByteCounter+2, 1):uint()
            subtree3:add (command_specific_byte1_field, buffer(ByteCounter+2, 1), "Reason:" .. get_bye_reason_display_text(ByeReason))
		
            infoColumnText = commandCodeName
			
		elseif CmdCode==BYE_REPLY_COMMAND_CODE then
            infoColumnText = commandCodeName
			
		elseif CmdCode==UMP_DATA_COMMAND_CODE then
			SequenceCounter = buffer (ByteCounter+2, 2):uint()
			subtree3:add (sequence_number_field, buffer(ByteCounter+2, 2), "Sequence Number:" .. SequenceCounter)
			
			-- Display UMP messages from the payload
			decode_ump_command (subtree3, buffer, ByteCounter, PayloadLengthWords)
			
			infoColumnText = commandCodeName
		else
			-- Unknown command : display raw content
			subtree3:add (payload_len_field, buffer(ByteCounter+1, 1), "Payload length")	
            
            infoColumnText = commandCodeName
		end
		
		-- Go to next packet, if there is one
		ByteCounter = ByteCounter + CommandHeaderSizeBytes + PayloadLengthBytes
		
		-- for single-command packets, we display in the info column
        if (ByteCounter >= buffer:len() and commandCount == 1) then
            pinfo.cols.info = infoColumnText
        elseif (ByteCounter >= buffer:len() and commandCount > 1) then
            pinfo.cols.info = "Multiple Command Packets"
        end
	end  -- while
	
	    -- for heuristic matching, returning a number > 0 means it's a match
    return ByteCounter
end		-- midi2_protocol.dissector
-- ---------------------------------

-- Associate this dissector to port 5004 by default
--local udp_port = DissectorTable.get("udp.port")
--udp_port:add(5004, midi2_protocol)
				
midi2_protocol:register_heuristic("udp", midi2_protocol.dissector)