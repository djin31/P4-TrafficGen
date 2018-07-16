--Template for addition of new protocol 'ipv4_option_NOP'

--[[ Necessary changes to other files:
-- - packet.lua: if the header has a length member, adapt packetSetLength; 
-- 				 if the packet has a checksum, adapt createStack (loop at end of function) and packetCalculateChecksums
-- - proto/proto.lua: add PROTO.lua to the list so it gets loaded
--]]

local ffi = require "ffi"
local dpdkc = require "dpdkc"

require "utils"
require "proto.template"
local initHeader = initHeader


local ntoh, hton = ntoh, hton
local ntoh16, hton16 = ntoh16, hton16
local bor, band, bnot, rshift, lshift= bit.bor, bit.band, bit.bnot, bit.rshift, bit.lshift
local istype = ffi.istype
local format = string.format

function hton64(int)
	int = int or 0
	endianness = string.dump(function() end):byte(7)
	if endianness==0 then
		return int
	end
	low_int = lshift(hton(band(int,0xFFFFFFFFULL)),32)
	high_int = rshift(hton(band(int,0xFFFFFFFF00000000ULL)),32)
	endianness = string.dump(function() end):byte(7)
	return (high_int+low_int)
end


local ntoh64, hton64 = ntoh64, hton64

----- 24 bit address -----
ffi.cdef[[
	union __attribute__((__packed__)) bitfield_24{
		uint32_t intequiv;
	};
]]

local bitfield24 = {}
bitfield24.__index = bitfield24
local bitfield24Type = ffi.typeof("union bitfield_24")

function bitfield24:get()
	return hton(self.intequiv)
end

function bitfield24:set(addr)
	addr = addr or 0
	self.intequiv = hton(tonumber(band(addr,0xFFFFFFFFULL)))

end

----- 40 bit address -----
ffi.cdef[[
	union __attribute__((__packed__)) bitfield_40{
		uint64_t intequiv;
	};
]]

local bitfield40 = {}
bitfield40.__index = bitfield40
local bitfield40Type = ffi.typeof("union bitfield_40")

function bitfield40:get()
	return hton64(self.intequiv)
end

function bitfield40:set(addr)
	addr = addr or 0
	self.intequiv = hton64(tonumber(band(addr,0xFFFFFFFFFFFFFFFFULL)))
end

----- 48 bit address -----
ffi.cdef[[
	union __attribute__((__packed__)) bitfield_48{
		uint32_t intequiv;
	};
]]

local bitfield48 = {}
bitfield48.__index = bitfield48
local bitfield48Type = ffi.typeof("union bitfield_48")

function bitfield48:get()
	return hton64(self.intequiv)
end

function bitfield48:set(addr)
	addr = addr or 0
	self.intequiv = hton64(tonumber(band(addr,0xFFFFFFFFFFFFFFFFULL)))
end


-----------------------------------------------------
---- IPV4_OPTION_NOP header and constants 
-----------------------------------------------------
local IPV4_OPTION_NOP = {}

IPV4_OPTION_NOP.headerFormat = [[
	uint8_t 	 value;
]]


-- variable length fields
IPV4_OPTION_NOP.headerVariableMember = nil

-- Module for IPV4_OPTION_NOP_address struct
local IPV4_OPTION_NOPHeader = initHeader()
IPV4_OPTION_NOPHeader.__index = IPV4_OPTION_NOPHeader


-----------------------------------------------------
---- Getters, Setters and String functions for fields
-----------------------------------------------------
function IPV4_OPTION_NOPHeader:getVALUE()
	return (self.value)
end

function IPV4_OPTION_NOPHeader:getVALUEstring()
	return self:getVALUE()
end

function IPV4_OPTION_NOPHeader:setVALUE(int)
	int = int or 0
	self.value = (int)
end



-----------------------------------------------------
---- Functions for full header
-----------------------------------------------------
-- Set all members of the PROTO header
function IPV4_OPTION_NOPHeader:fill(args,pre)
	args = args or {}
	pre = pre or 'IPV4_OPTION_NOP'

	self:setVALUE(args[pre .. 'VALUE'])
end

-- Retrieve the values of all members
function IPV4_OPTION_NOPHeader:get(pre)
	pre = pre or 'IPV4_OPTION_NOP'

	local args = {}
	args[pre .. 'VALUE'] = self:getVALUE()

	return args
end

function IPV4_OPTION_NOPHeader:getString()
	return 'IPV4_OPTION_NOP \n'
		.. 'VALUE' .. self:getVALUEString() .. '\n'
end

-- Dictionary for next level headers
local nextHeaderResolve = {
}
function IPV4_OPTION_NOPHeader:resolveNextHeader()
	return scalars
end


-----------------------------------------------------
---- Metatypes
-----------------------------------------------------
ffi.metatype('union bitfield_24',bitfield24)
ffi.metatype('union bitfield_40',bitfield40)
ffi.metatype('union bitfield_48',bitfield48)IPV4_OPTION_NOP.metatype = IPV4_OPTION_NOPHeader

return IPV4_OPTION_NOP