description = [[
This performs a host discovery on the network and tries to obtain the hostname using various means such as NETBIOS, SMB etc., 
]]

---
-- @usage
-- nmap --script hostinfo-discover.nse -p T:139,445,U:137 <hosts/networks>
--
-- @output
-- Post-scan script results:
-- |   HOST        LOOKUP                    NETBIOS_NAME                SMB_NAME
-- |   10.1.0.1                              Name query failed: TIMEOUT  nil
-- |   10.1.0.156  NAS.cromulon              NAS                         NAS
-- |   10.1.0.180  xkgt-arch.cromulon        Name query failed: ERROR    nil
-- |   10.1.0.200                            Name query failed: ERROR    nil
-- |   10.1.0.77   xkgt-Swanky.cromulon      Name query failed: ERROR    nil
-- |   10.1.0.88   DESKTOP-23HUSOR.cromulon  DESKTOP-23HUSOR             nil
-- |_  10.1.0.254  wall.cromulon             Name query failed: TIMEOUT  nil
-- Version 0.1
-- Created 05/11/2017 - v0.1 - created by Tamizh
--
-- TODO: Add other discovery methods such as SNMP, LLMNR, MDNS
-- TODO: Return best guestimate for hostname or a list of hostname if the
-- value reported by each protocol differs

author = "Tamizh"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


local shortport = require "shortport"
local http = require "http"
local smb  = require "smb"
local stdnse = require "stdnse"
local ipOps = require "ipOps"
local netbios = require "netbios"
local tab = require "tab"
local table = require "table"
local snmp = require "snmp"

-- The Rule Section --
postrule = function() return true end
hostrule = function() return true end

local output_structured = {}
local output = tab.new()

-- The Action Section --

local function sort_ip_ascending(a, b)
  return ipOps.compare_ip(a, "lt", b)
end

local function get_smb_name(host)
    local smb_name = nil
    local smb_status, smb_result = smb.get_os(host)
    if smb_status then
        if smb_result then
           smb_name = smb_result.server
        end
    end
    return smb_name
end

local function get_netbios_name(host)
    local nbt_status, netbios_name = netbios.get_server_name(host)
    if nbt_status then
        return netbios_name
    else
        return nil
    end
end

hostaction = function(host)
    nmap.registry[SCRIPT_NAME] = nmap.registry[SCRIPT_NAME] or {}
    local smb_status, smb_result = smb.get_os(host)
    local ip = host.ip
    local name = host.name
    local smb_name, netbios_name = nil
    local smb_name = get_smb_name(host)
    local netbios_name = get_netbios_name(host)
    local db = nmap.registry[SCRIPT_NAME]
    db[ip] = db[ip] or {}
    table.insert(db[ip], { rlookup = name,nbt = netbios_name, smb = smb_name })
end

postaction = function()
	local db = nmap.registry[SCRIPT_NAME]
    local order = stdnse.keys(db)
    table.sort(order, sort_ip_ascending )
    tab.addrow(output, 'HOST' , 'LOOKUP', 'NETBIOS_NAME', 'SMB_NAME')
    for _, ip in ipairs(order) do
        for _, entry in ipairs(db[ip]) do
            tab.addrow(output, ip, entry['rlookup'], entry['nbt'], entry['smb'])
        end
    end
    output = tab.dump(output)
    return stdnse.format_output(true, output)
end


local Actions = {
  hostrule = hostaction,
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return Actions[SCRIPT_TYPE](...) end
