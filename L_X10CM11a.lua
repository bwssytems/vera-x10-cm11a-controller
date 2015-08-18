module("L_X10CM11a", package.seeall)

local CM11_SID    = "urn:micasaverde-com:serviceId:CM11"
local SECURITY_SID  = "urn:micasaverde-com:serviceId:SecuritySensor1"
local SWITCHPWR_SID = "urn:upnp-org:serviceId:SwitchPower1"
local HADEVICE_SID  = "urn:micasaverde-com:serviceId:HaDevice1"
local DIMMING_SID   = "urn:upnp-org:serviceId:Dimming1"
local DEBUG_MODE = false

local controller_id
local child_id_lookup_table = {}

------------------------------------------------------------
local function trim(s)
  return s:gsub("^%s*", ""):gsub("%s*$","")
end

------------------------------------------------------------
local function log(text, level)
    luup.log("X10CM11a: " .. text, (level or 50))
end

------------------------------------------------------------
local function debug(text)
  if (DEBUG_MODE == true) then
      log("debug: " .. (text or "<empty>"), 50)
  end
end

------------------------------------------------------------
local function x10_id(dev_id)
   local xid =  dev_id:sub(3)
   return xid
end

------------------------------------------------------------
local function x10_type(dev_id)
   local xtype =  dev_id:sub(1,2)
   return xtype
end

------------------------------------------------------------
-- convert a 'sep' seperated string into a lua list
local function split_deliminated_string(s,sep)
    if s==nil then
        return {}
    end
    s = s .. sep        -- ending seperator
    local t = {}        -- table to collect fields
    local fieldstart = 1
    repeat
        local nexti = string.find(s, sep, fieldstart)
        table.insert(t, string.sub(s, fieldstart, nexti - 1))
        fieldstart = nexti + 1
    until fieldstart > string.len(s)
    return t
end

------------------------------------------------------
-- Bitwise functions; used and adapted from bit lib --
------------------------------------------------------
local function check_int(n)
    -- checking not float
    if(n - math.floor(n) > 0) then
        error("trying to use bitwise operation on non-integer!")
    end
end

local function tbl_to_number(tbl)
    local n = table.getn(tbl)

    local rslt = 0
    local power = 1
    for i = 1, n do
        rslt = rslt + tbl[i]*power
        power = power*2
    end

    return rslt
end

local function expand(tbl_m, tbl_n)
    local big = {}
    local small = {}
    if (table.getn(tbl_m) > table.getn(tbl_n)) then
        big = tbl_m
        small = tbl_n
    else
        big = tbl_n
        small = tbl_m
    end
    -- expand small
    for i = table.getn(small) + 1, table.getn(big) do
        small[i] = 0
    end
end

local function tobits(n)
    -- to bits table
    local tbl = {}
    local cnt = 1

    if (n == 0) then
        tbl = {0, 0, 0, 0, 0, 0, 0, 0} -- I need an array, even if = 0
        return tbl
    end

    while (n > 0) do
        local last = math.mod(n, 2)
        if (last == 1) then
            tbl[cnt] = 1
        else
            tbl[cnt] = 0
        end
        n = (n - last)/2
        cnt = cnt + 1
    end

    if (#tbl < 8) then
        for i = (#tbl + 1), 8, 1 do   -- complete the 8 bits arrays
            tbl[i] = 0
        end
    end

    return tbl
end

local function band(m,n)
    local tbl_m = tobits(m)
    local tbl_n = tobits(n)
    expand(tbl_m, tbl_n)

    local tbl = {}
    local rslt = math.max(table.getn(tbl_m), table.getn(tbl_n))
    for i = 1, rslt do
        if(tbl_m[i] == 0 or tbl_n[i] == 0) then
            tbl[i] = 0
        else
            tbl[i] = 1
        end
    end

    return tbl_to_number(tbl)
end

local function bitnot(n)

    local tbl = tobits(n)
    local size = math.max(table.getn(tbl), 32)
    for i = 1, size do
        if(tbl[i] == 1) then
            tbl[i] = 0
        else
            tbl[i] = 1
        end
    end
    return tbl_to_number(tbl)
end

local function bit_lshift(n, bits)
    check_int(n)

    if(n < 0) then
        -- negative
        n = bitnot(math.abs(n)) + 1
    end

    for i = 1, bits do
        n = n * 2
    end

    return band(n, 4294967295) -- 0xFFFFFFFF
end

-------------------
-- X10 functions --
-------------------

local function addresscode_code(housecode, unitcode)

    -- This function return House code & device code (i.e. C3) from Hex value.

    -- Table with house & devices codes as per X10 protocol
    local housecodes_X10 ={ A = 96, B = 224, C = 32, D = 160, E = 16, F = 144, G = 80, H = 208,
                            I = 112, J = 240, K = 48, L = 176, M = 0, N = 128, O = 64, P = 192}
    local devicecodes_X10 = {6, 14, 2, 10, 1, 9, 5, 13, 7, 15, 3, 11, 0, 8, 4, 12}

    local code_house

    -- get house code
    -- search housecode
    for j,v in pairs(housecodes_X10) do
        if j == housecode then
            code_house = v
            break
        end
    end

    -- get device code

    local code_unit = devicecodes_X10[tonumber(unitcode)]

    local addresscode1 = '04' -- to identify single device
    
    if(unitcode == '') then
      code_unit = 0
    end
    local addresscode2 = string.format("%02X",(code_unit + code_house))

    local addresscode = addresscode1 .. addresscode2
    local checksum = tonumber(addresscode1, 16) + tonumber(addresscode2, 16)
    checksum = band(checksum, 0xFF)

    -- return variables
    return addresscode, checksum
end

local function functioncode_code(housecode, unitcode, functcode, functvalue)
    log("functioncode_code: housecode = " .. housecode .. ", unitcode = " .. unitcode .. ", functcode = " .. functcode .. ", functvalue = " .. functvalue, 50)
    -- This function return House code & function code (i.e. B Dim) from Hex value.

    -- Function             Binary Value
    -- All Units Off        0000
    -- All Lights On        0001
    -- On                   0010
    -- Off                  0011
    -- Dim                  0100
    -- Bright               0101
    -- All Lights Off       0110
    -- Extended Code        0111
    -- Hail Request         1000
    -- Hail Acknowledge     1001
    -- Pre-set Dim (1)      1010
    -- Pre-set Dim (2)      1011
    -- Extended Data Transfer 1100
    -- Status On            1101
    -- Status Off           1110
    -- Status Request       1111

    -- Table with house & function codes as per X10 protocol
    local housecodes_X10 ={A = 96, B = 224, C = 32, D = 160, E = 16, F = 144, G = 80,
                           H = 208, I = 112, J = 240, K = 48, L = 176, M = 0, N = 128, O = 64, P = 192}
    local functioncodes_X10 = {["On"] = 2, ["Off"] = 3, ["Dim"] = 4, ["Bright"] = 5, ["All Units Off"] = 0,
                               ["All Lights On"] = 1, ["All Lights Off"] = 6, ["EXT"] = 7, ["PRESETDIM1"] = 10,
                               ["PRESETDIM2"] = 11, ["STATUSREQ"] = 15}
    local devicecodes_X10 = {6, 14, 2, 10, 1, 9, 5, 13, 7, 15, 3, 11, 0, 8, 4, 12}

    local code_house
    local code_function

    -- search housecode
    for j,v in pairs(housecodes_X10) do
        if j == housecode then
            code_house = v
            break
        end
    end

    -- search functioncode
    for j,v in pairs(functioncodes_X10) do
        if j == functcode then
            code_function = v
            break
        end
    end

    -- get unitcode
    local code_unit = devicecodes_X10[tonumber(unitcode)]
    if(unitcode == '') then
      code_unit = 0
    end

    -- return variables (default)
    local functioncode2 = string.format("%02X",(code_house + code_function))
    local functioncode1 = string.format("%02X", 6) -- hex value for function value
    local checksum = tonumber(functioncode1, 16) + tonumber(functioncode2, 16)
    checksum = band(checksum, 0xFF)

    if (functcode == 'EXT') then
        if (functvalue == nil or tonumber(functvalue) > 63) then
            functvalue = '63'
        elseif(tonumber(functvalue) < 0) then
            functvalue = '0'
        end

        local headerbyte = 7 -- 7 is for extended code
        functioncode1 = string.format("%02X", headerbyte)

        local extunit = string.format("%02X", code_unit) -- unit code in lower nibble
        local extcode = string.format("%X", 49) -- 00110001 Type 3 = Control Modules Func 1 = Preset Receiver
        local extdata = string.format("%02X", tonumber(functvalue))

        checksum = tonumber(functioncode1, 16) + tonumber(functioncode2, 16) + tonumber(extunit, 16) + tonumber(extdata, 16) + tonumber(extcode, 16)
        checksum = band(checksum, 0xFF)

        functioncode2 = functioncode2 .. extunit .. extdata .. extcode

    elseif (functcode == 'PRESETDIM1' or functcode == 'PRESETDIM2') then
        log("functioncode_code: in preset dim section", 50)
        if (functvalue == nil or tonumber(functvalue) > 31) then
            functvalue = 31
        elseif(tonumber(functvalue) < 0) then
            functvalue = 0
        end

        functioncode2 = string.format("%02X", functvalue * 16 + code_function)
        checksum = tonumber(functioncode1, 16) + tonumber(functioncode2, 16)
        checksum = band(checksum, 0xFF)

    elseif (functcode == 'Bright' or functcode == 'Dim') then
        -- protect function value
        if (functvalue == nil or tonumber(functvalue) > 22) then
            functvalue = '22'
        elseif (tonumber(functvalue) < 0) then
            functvalue = '0'
        end

        local dimvalue_1 = math.floor(tonumber(functvalue))
        local dimvalue_2 = bit_lshift(dimvalue_1,3)
        local dimvalue = dimvalue_2 +6  -- 6 is 1, F=1, S=0 (110)

        functioncode1 = string.format ("%02X",dimvalue)
        checksum = tonumber(functioncode1, 16) + tonumber(functioncode2, 16)
        checksum = band(checksum, 0xFF)
    end

    local functioncode = functioncode1 .. functioncode2
    return functioncode, checksum

end

local function addresscode_decode(code)
-- This function return House code & device code (i.e. C3) from Hex value.

    -- Table with house & devices codes as per X10 protocol
    local housecodes_X10 ={A = 96, B = 224, C = 32, D = 160, E = 16, F = 144, G = 80,
                           H = 208, I = 112, J = 240, K = 48, L = 176, M = 0, N = 128, O = 64, P = 192}
    local devicecodes_X10 = {6, 14, 2, 10, 1, 9, 5, 13, 7, 15, 3, 11, 0, 8, 4, 12}

    -- get house code
    local decimalcode = tonumber(code,16)
    local mask = 240 -- 240 is '11110000'
    local basecode = band(decimalcode, mask)

    local housecode
    local devicecode

    -- search housecode
    for j, v in pairs(housecodes_X10) do
        if (v == basecode) then
            housecode = j
            break
        end
    end

    -- get device code
    decimalcode = tonumber(code,16)
    mask = 15 -- 15 is '00001111'
    basecode = band(decimalcode, mask)

    -- search devicecode
    for j, v in pairs(devicecodes_X10) do
        if (v == basecode) then
            devicecode = j
            break
        end
    end

    -- return variables
    return housecode, devicecode
end

local function functioncode_decode(code)
    -- This function return House code & function code (i.e. B Dim) from Hex value.

    -- Function                 Binary Value
    -- All Units Off            0000
    -- All Lights On            0001
    -- On                       0010
    -- Off                      0011
    -- Dim                      0100
    -- Bright                   0101
    -- All Lights Off           0110
    -- Extended Code            0111
    -- Hail Request             1000
    -- Hail Acknowledge         1001
    -- Pre-set Dim (1)          1010
    -- Pre-set Dim (2)          1011
    -- Extended Data Transfer   1100
    -- Status On                1101
    -- Status Off               1110
    -- Status Request           1111

    -- Table with house & function codes as per X10 protocol
    local housecodes_X10 ={A = 96, B = 224, C = 32, D = 160, E = 16, F = 144, G = 80, H = 208,
                           I = 112, J = 240, K = 48, L = 176, M = 0, N = 128, O = 64, P = 192}
    local functioncodes_X10 = {["On"] = 2, ["Off"] = 3, ["Dim"] = 4, ["Bright"] = 5, ["All Units Off"] = 0 ,
                               ["All Lights On"] = 1, ["All Lights Off"] = 6, ["EXT"] = 7, ["PRESETDIM1"]=10,
                               ["PRESETDIM2"] = 11, ["EXTDATAXFER"] = 12, ["STATUSON"] = 13, ["STATUSOFF"] = 14, ["STATUSREQ"] = 15}

    -- get house code
    local decimalcode = tonumber(code, 16)
    local mask = 240 -- 240 is '11110000'
    local basecode = band(decimalcode, mask)

    local housecode
    local functioncode

    -- search housecode
    for j, v in pairs(housecodes_X10) do
        if (v == basecode) then
            housecode = j
            break
        end
    end

    -- get function code
    decimalcode = tonumber(code,16)
    mask = 15 -- 15 is '00001111'
    basecode = tonumber (band(decimalcode, mask))

    -- search functioncode
    for j, v in pairs(functioncodes_X10) do
        if (v == basecode) then
            functioncode = j
            break
        end
    end

    -- return variables
    return housecode, functioncode
end

local function dbuffer_index(mask_index)
    return(mask_index + 2)
end

------------------------------------------------------------
local function is_type(dev, type)
  local named_devs = luup.variable_get(CM11_SID, type, controller_id)
  debug("is_type: dev: " .. dev .. ", type: " .. type)
  if( named_devs==nil ) then
      debug("is_type: named_devs is nil.")
      return false
  end
  t = split_deliminated_string(named_devs,',')
  for i,element in ipairs(t) do
      debug("is_type: check dev with element: " .. element)
      if element == dev then
          debug("is_type: dev found, returning true.")
          return true
      end
  end
  debug("is_type: dev not found, returning false.")
  return false
end

------------------------------------------------------------
local function update_dim_level(cm11type, x10addr, new_load_value)
    local altid = cm11type .. x10addr
    debug("update_dim_level: This is the alt id: " .. altid .. " to LoadLevelStatus: " .. tostring(new_load_value))
    luup.variable_set(DIMMING_SID, "LoadLevelStatus", new_load_value, child_id_lookup_table[altid])
    if(new_load_value > 0) then
        luup.variable_set(SWITCHPWR_SID, "Status", '1', child_id_lookup_table[altid])
    end
end

------------------------------------------------------------
local function update_light_toggle(cm11type, x10addr, new_state)
    local altid = cm11type .. x10addr
    local new_dim    = ((new_state == 'On') and 100 or 0)
    local new_toggle = ((new_state == 'On') and '1' or '0')
    debug("update_light_toggle: This is the alt id: " .. altid ..", this is the new dim: " .. new_dim .. " and new toggle: " .. new_toggle)
    luup.variable_set(SWITCHPWR_SID,"Status", new_toggle, child_id_lookup_table[altid])
    if (not is_type(x10addr, "BinaryModules")) then
        luup.variable_set(DIMMING_SID, "LoadLevelStatus", new_dim, child_id_lookup_table[altid])
    end
end

local function manage_actions(x10addr, funct_settings)
    local new_state = funct_settings["function"]
    if (x10addr == nil) then
        log("manage_actions: no entry in child_id_lookup_table for " .. x10addr)
    else
        debug("manage_actions: x10addr: " .. x10addr .. ", new_state: " .. new_state)
        -- Handle Dim/Bright commands
        if ((new_state == 'Dim') or ((new_state == 'Bright'))) then
            local new_load_value = funct_settings["functionData"]
            new_load_value = tonumber(new_load_value)

            -- and set the new level
            if (is_type(x10addr, "DimmableModules")) then
                update_dim_level('D-', x10addr, new_load_value)
            end
            if (is_type(x10addr, "SoftstartModules")) then
                update_dim_level('X-', x10addr, new_load_value)
            end
        end

        -- Handle Motion Sensors
        if (is_type(x10addr, "MotionSensors")) then
            local tripped = ((new_state == 'On') and '1' or '0')
            luup.variable_set(SECURITY_SID, "Tripped", tripped, child_id_lookup_table['M-' .. x10addr])
        end

         -- Handle Binary Modules
        if (is_type(x10addr, "BinaryModules")) then
            update_light_toggle('A-', x10addr, new_state)
        end

        if((new_state == 'On') or (new_state == 'Off')) then
            debug("manage_actions: handle on/off for Dimmables - x10addr: " .. x10addr .. ", new_state: " .. new_state)
            -- Handle Dimmable Modules
            if (is_type(x10addr, "DimmableModules")) then
                debug("manage_actions: is a dimmable module - x10addr: " .. x10addr .. ", new_state: " .. new_state)
                update_light_toggle('D-', x10addr, new_state)
            end

            -- Handle SoftStart Modules
            if (is_type(x10addr, "SoftstartModules")) then
                debug("manage_actions: is a softstart module - x10addr: " .. x10addr .. ", new_state: " .. new_state)
                update_light_toggle('X-', x10addr, new_state)
            end
        end
    end
end

local function decode_buffer_x10(buffer_CM11)

    local buffer = split_deliminated_string(buffer_CM11,' ')
    -- this can happen!
    if (buffer == nil) then
        return
    end

    log ('decode_buffer_x10: incoming buffer size:'.. tostring(buffer[1]), 50)

    -- Init tables. One for addresses commands, another one for functions and the last one for cross-reference betwenn them
    local addresses_table = {}
    local functions_table = {}
    local cross_address_function_table = {}

    -- Get number of bytes (Function or address) to process
    local no_of_bytes = (tonumber(buffer[1], 16) - 1)  -- No of actual data bytes to process. First on is no of bytes, second one is masks byte

    -- Create bit mask table
    local bit_mask_byte = tonumber(buffer[2],16)
    local bit_mask_table  = tobits(bit_mask_byte)

    -- init indexes
    local addr_index = 1;
    local funct_index = 1;

    -- Init cross matrix
    cross_address_function_table[1] = 1

    -- Decode buffer commands
    local mask_index = 1  -- index in mask bytes

    local housecode
    local devicecode
    local address_code
    local function_target

    repeat
        if (bit_mask_table[mask_index] == 0) then -- address code detected
            -- get both house and unit/device codes.

            housecode, devicecode = addresscode_decode(buffer[dbuffer_index(mask_index)])
            -- built full device code
            address_code = (housecode .. devicecode)
            log ('decode_buffer_x10: address detected: '.. address_code, 50)

            -- store it.
            addresses_table[addr_index] = address_code
            -- store associated function
            cross_address_function_table[addr_index] = funct_index

            addr_index = addr_index + 1
            mask_index = mask_index + 1 -- next byte

        elseif  bit_mask_table[mask_index] == 1 then -- function code detected
            housecode, function_target = functioncode_decode(buffer[dbuffer_index(mask_index)])
            log ('decode_buffer_x10: function detected: '.. function_target, 50)

            if (function_target == 'Dim') then
                mask_index = mask_index + 1 -- another byte
                local dimvalue_raw = tonumber(buffer[dbuffer_index(mask_index)], 16);
                -- 0x58     0x58/210 * 100%
                local dimvalue = math.floor((dimvalue_raw / 210) * 100)

                functions_table[funct_index] = {["function"] = function_target, ["functionData"] = tostring(dimvalue)}

            elseif (function_target == 'Bright') then
                mask_index = mask_index + 1 -- another byte
                local brightvalue_raw = tonumber(buffer[dbuffer_index(mask_index)], 16);
                local brightvalue = math.floor((brightvalue_raw / 210) * 100)

                functions_table[funct_index] = {["function"] = function_target, ["functionData"] = tostring(brightvalue)}

            elseif (function_target == 'EXT') then
                mask_index = mask_index + 1

                local databyte_raw = tonumber(buffer[dbuffer_index(mask_index)], 16);
                mask_index = mask_index + 1 -- bypass control byte as we don't need it

                if (databyte_raw == 0) then
                    functions_table[funct_index] = {["function"] = 'Off', ["functionData"] = ""}
                else
                    local dimpct = math.floor(databyte_raw / 63 * 100)
                    functions_table[funct_index] = {["function"] = function_target, ["functionData"] = tostring(dimpct)}
                end

            elseif (function_target == 'PRESETDIM1' or function_target == 'PRESETDIM2') then
                -- housecode is actually the preset dim amount
                local pdimcodes_X10 = {M = 0, N = 1, O = 2, P = 3, C = 4, D = 5, A = 6, B = 7,
                                       E = 8, F = 9, G = 10, H = 11, K = 12, L = 13, I = 14, J = 15}

                local dimval = pdimcodes_X10[housecode]

                if (function_target == 'PRESETDIM2') then
                    dimval = dimval + 16
                end

                if (dimval == 0) then
                    functions_table[funct_index] = {["function"] = 'Off', ["functionData"] = ""}
                else
                    local dimpct = math.floor(dimval / 31 * 100)
                    functions_table[funct_index] = {["function"] = function_target, ["functionData"] = tostring(dimpct)}
                end

            elseif (function_target == 'On' or function_target == 'Off' or function_target == 'STATUSON' or function_target == 'STATUSOFF') then -- simple function
                functions_table[funct_index] = {["function"] = function_target, ["functionData"] = ""}

            elseif  (function_target == 'All Lights On' or function_target == 'All Units Off' or function_target == 'All Lights Off' ) then -- simple function
                functions_table[funct_index] = {["function"] = function_target, ["functionData"] = ""}

            else
                -- Not yet supported function, discard.
                return
            end

            funct_index = funct_index + 1
            mask_index = mask_index + 1 -- next byte
        end

    until (mask_index > no_of_bytes) -- -2 because 1 for byte number and 1 for masks byte.

    -- Build full action commands
    local no_of_cmds = addr_index - 1

    if (no_of_cmds == 0) then  -- No address, so functions
        no_of_cmds = funct_index - 1
    end

    -- Decode to get action commands
    -- get previous/old commands. CM11/X10 devices could send the command in two strings, one for address and one for Function
    -- It is necessary to keep the first one to compose the full action command
    local old_addr = luup.variable_get(CM11_SID, "old_addr_cmd", controller_id)
    local old_funct = luup.variable_get(CM11_SID, "old_funct_cmd", controller_id)
    local old_funct_data = luup.variable_get(CM11_SID, "old_funct_data", controller_id)

    for j = 1, no_of_cmds, 1 do

        local cross_index = cross_address_function_table[j]

        -- Init action_settings table
        local action_settings = {}
        local addr_cmd
        local funct_cmd

        -- Build action commands from buffer decoding
        if (addresses_table[j] ~= nil and functions_table[cross_index] == nil and old_funct ~="") then
            addr_cmd = addresses_table[j]
            action_settings["function"] = old_funct
            action_settings["functionData"] = old_funct_data
            -- Once action command is available, perform action.
            manage_actions(addr_cmd, action_settings)

        elseif (functions_table[cross_index] ~= nil and addresses_table[j]== nil and old_addr ~="") then
            addr_cmd = old_addr
            funct_cmd = functions_table[cross_index]
            action_settings["function"] = funct_cmd["function"]
            action_settings["functionData"] = funct_cmd["functionData"]
            -- Once action command is available, perform action.
            manage_actions(addr_cmd, action_settings)

        elseif (addresses_table[j] ~= nil and functions_table[cross_index] ~= nil) then
            luup.variable_set(CM11_SID, "old_funct_cmd", "", controller_id)
            luup.variable_set(CM11_SID, "old_funct_data", "", controller_id)
            luup.variable_set(CM11_SID, "old_addr_cmd", "", controller_id)

            addr_cmd = addresses_table[j]
            funct_cmd = functions_table[cross_index]
            action_settings["function"] = funct_cmd["function"]
            action_settings["functionData"] = funct_cmd["functionData"]

            -- Once action command is available, perform action.
            manage_actions(addr_cmd, action_settings)

        elseif (addresses_table[j] == nil and functions_table[cross_index] ~= nil) then
            funct_cmd = functions_table[cross_index]
            luup.variable_set(CM11_SID, "old_funct_cmd", funct_cmd["function"], controller_id)
            luup.variable_set(CM11_SID, "old_funct_data", funct_cmd["functionData"], controller_id)

        elseif (functions_table[cross_index] == nil and addresses_table[j] ~= nil) then
            luup.variable_set(CM11_SID, "old_addr_cmd", addresses_table[j], controller_id)
        else
            -- Discard command
        end
    end
end


local function sendCommand_direct_x10(command)
-- Send direct command to CM11.

    if (luup.io.write(command) == false) then
        luup.set_failure(true)
        luup.sleep(1000)
        return false
    else
        luup.sleep(1000)
    end
end


-------------
-- STARTUP --
-------------
------------------------------------------------------------
local function add_children(parent, child_list_ptr, prefix, schema, dev_file, dev_type, csv_dev_list)
  local dev_list = split_deliminated_string(csv_dev_list,',')
  for idx, dev_name in ipairs(dev_list) do
      dev_name = trim(dev_name)
      if (dev_name and dev_name ~= "") then
         debug("Adding " .. dev_type .. " " .. dev_name)
         luup.chdev.append(parent, child_list_ptr, prefix .. dev_name, "X10 " .. dev_name, schema, dev_file, "", "", false)
      end
   end
end

function startup(lul_device)

    log("Entering startup", 50)

    controller_id = lul_device

    --Init/reset variables that control polling
    init_polling ('1') -- '1' means init variables

    -- Init variables to manage action commands
    luup.variable_set(CM11_SID, "old_funct_cmd", "", lul_device)
    luup.variable_set(CM11_SID, "old_funct_data", "", lul_device)
    luup.variable_set(CM11_SID, "old_addr_cmd", "", lul_device)

     ------------------------------------------------------------
     -- Create a new Child Device List
     child_devices = luup.chdev.start(lul_device);
     ------------------------------------------------------------

     -- Vera gets angry with me when I accidently add two child devices
     -- with the same name but different schemas. (as well it should!)
     -- To avoid that I am appending a prefix before the X10 code of the child device
     -- A-A01 is an applicance module at A01
     -- D-A01 is a dimmer at A01
     -- X-A01 is a dimmer at A01
     -- M-A01 is a motion sensor at A01

     ---------------
     -- Get a list of child devices
     local app_ID     = luup.variable_get(CM11_SID, "BinaryModules",      lul_device)
     local housectl_ID = luup.variable_get(CM11_SID, "HouseCtlModules",   lul_device)
     local dim_ID     = luup.variable_get(CM11_SID, "DimmableModules",    lul_device)
     local xdim_ID    = luup.variable_get(CM11_SID, "SoftstartModules",   lul_device)
     local motion_ID  = luup.variable_get(CM11_SID, "MotionSensors",      lul_device)

     ---------------
     -- If all child devices are empty add a few examples
     if (app_ID == nil) then
          luup.variable_set(CM11_SID, "BinaryModules",      "",        lul_device)
      end
     if (housectl_ID == nil) then
          luup.variable_set(CM11_SID, "HouseCtlModules",      "",        lul_device)
      end
     if (dim_ID == nil) then
          luup.variable_set(CM11_SID, "DimmableModules",    "",        lul_device)
      end
     if (xdim_ID == nil) then
          xdim_ID = "A1,A2"
          luup.variable_set(CM11_SID, "SoftstartModules",   xdim_ID,   lul_device)
      end
      if (motion_ID == nil) then
          motion_ID = "M1,M2"
          luup.variable_set(CM11_SID, "MotionSensors",      motion_ID, lul_device)
      end

     ------------------------------------------------------------
     -- APPLIANCE MODULES
     add_children(lul_device, child_devices, 'A-', "",  "D_BinaryLight1.xml",  "Binary Light", app_ID)
     -- House Ctl MODULES
     add_children(lul_device, child_devices, 'H-', "",  "D_BinaryLight1.xml",  "House Ctl Switch", housectl_ID)
     -- DIMMABLE LIGHTS
     add_children(lul_device, child_devices, 'D-', "", "D_DimmableLight1.xml", "Dimmable Light", dim_ID)
     -- SOFTSTART DIMMABLE LIGHTS --
     add_children(lul_device, child_devices, 'X-', "", "D_DimmableLight1.xml", "Dimmable Light", xdim_ID)
     -- MOTION SENSORS --
     add_children(lul_device, child_devices, 'M-', "",  "D_MotionSensor1.xml",  "Motion Sensor", motion_ID)

     luup.chdev.sync(lul_device, child_devices)

     ------------------------------------------------------------
     -- Find my children and build lookup table of altid -> id
     ------------------------------------------------------------
     -- loop over all the devices registered on Vera
     for k, v in pairs(luup.devices) do
         -- if I am the parent device
         if v.device_num_parent == luup.device then
             debug('Found Child ID: ' .. k .. ' AltID: ' .. v.id)
             child_id_lookup_table[v.id] = k
         end
     end

     log("Finished startup", 50)

end

---------------------
-- Handle Actions: --
---------------------

function sendX10Command(lul_settings)

    -- This functions build string/commands to be sent to sent from Vera commands

    log("SendX10Command: init")

    local house_unit_codes = lul_settings["x10_id"]
    local functcode = lul_settings["command"]
    local functvalue= lul_settings["data"]

    if (functvalue == nil) then
      functvalue = ""
    end

    local comm_str1 = ''
    local comm_str2 = ''
    local housecode = ""
    local unitcode = ""

    housecode = string.sub(house_unit_codes, 1, 1) -- i.e A
    unitcode = string.sub(house_unit_codes, 2) -- i.e. 15

    -- Build X10 commands
    local comm_str1_raw
    local addr_chksum
    local comm_str2_raw
    local func_chksum

    comm_str1_raw, addr_chksum = addresscode_code(housecode, unitcode)
    comm_str2_raw, func_chksum = functioncode_code(housecode, unitcode, functcode, functvalue)

    log("sendX10Command: comm_str1_raw/chksum = " .. comm_str1_raw .. "/" .. string.format("%X", addr_chksum), 50)
    log("sendX10Command: comm_str2_raw/chksum = " .. comm_str2_raw .. "/" .. string.format("%X", func_chksum), 50)

    -- Convert to hex characters to send to serial to CM11 (specific format)
    -- str1 to CM11
    local comm_str1_length = string.len(comm_str1_raw)
    for i = 1,comm_str1_length,2 do
        comm_str1 = comm_str1 .. string.char('0x' .. string.sub(comm_str1_raw,i,i+1))
    end

    -- str2 to CM11
    local comm_str2_length = string.len(comm_str2_raw)
    for i = 1,comm_str2_length,2 do
        comm_str2 = comm_str2 .. string.char('0x' .. string.sub(comm_str2_raw,i,i+1))
    end

    -- Make sure we aren't in polling mode getting data from the CM11
    local polling = luup.variable_get(CM11_SID, "Polling_status", controller_id)
    if (polling == "1") then
        return 0, 1  -- wait and try again in one second
    end

    -- retry up to three times to send data and get a valid checksum
    local goodchksum = false
    local recvd_data
    local recvd_byte

    for retries = 1, 3 do
        luup.io.intercept()

        -- Write in serial line to CM11
        if (luup.io.write(comm_str1) == false) then
            log("sendX10Command: Fail to send x10 init bytes", 50)
            return 2, nil
        end

        recvd_data = luup.io.read()

        if (recvd_data == nil) then
            log("sendX10Command: read() got nil response for chksum", 50)
            return 2, nil
        end

        if (string.len(recvd_data) > 1) then
            log("sendX10Command: received too many bytes (>1) for address checksum", 50)
            return 2, nil
        end

        recvd_byte = string.byte(recvd_data, 1, 1)
        recvd_byte = tonumber(recvd_byte)

        if (recvd_byte == addr_chksum) then
            goodchksum = true
            break
        else
            log("sendX10Command: try " .. retries .. " bad addr checksum, got: " .. string.format("0x%X", recvd_byte) .. " expected: " .. string.format("0x%X", addr_chksum))
        end
    end

    if (goodchksum == false) then
        return 2, nil
    end

    -- Send 0x00 and wait for 0x55 response
    luup.io.intercept()

    if (luup.io.write(string.char(0x00)) == false) then
        log("sendX10Command: Fail to send 0x00 ack byte", 50)
        return 2, nil
    end

    recvd_data = luup.io.read()

    if (recvd_data == nil) then -- timeout
        log("sendX10Command: read() got nil instead of 0x55 response", 50)
        return 2, nil
    end

    if (string.len(recvd_data) > 1) then
        log("sendX10Command: received too many bytes (>1) for inteface ready", 50)
        return 2, nil
    end

    recvd_byte = string.byte(recvd_data, 1, 1)
    recvd_byte = tonumber(recvd_byte)

    if (recvd_byte ~= 0x55) then
        log("sendX10Command: bad interface ready byte. Got " .. tostring(recvd_byte) .. ", expected 85 (0x55)", 50)
        return 2, nil
    end

    -- Send the function command

    -- retry up to three times to send data and get a valid checksum
    goodchksum = false

    for retries = 1, 3 do
        luup.io.intercept()

        -- Write in serial line to CM11
        if (luup.io.write(comm_str2) == false) then
            log("sendX10Command: Fail to send x10 func bytes", 50)
            return 2, nil
        end

        recvd_data = luup.io.read()

        if (recvd_data == nil) then -- timeout
            log("sendX10Command: read() nil received for chksum", 50)
            return 2, nil
        end

        if (string.len(recvd_data) > 1) then
            log("sendX10Command: received too many bytes (>1) for address checksum", 50)
            return 2, nil
        end

        recvd_byte = string.byte(recvd_data, 1, 1)
        recvd_byte = tonumber(recvd_byte)

        if (recvd_byte == func_chksum) then
            goodchksum = true
            break
        else
            log("sendX10Command: try " .. retries .. " bad func checksum, got: " .. string.format("0x%X", recvd_byte) .. " expected: " .. string.format("0x%X", func_chksum))
        end
    end

    if (goodchksum == false) then
        return 2, nil
    end

    -- Send 0x00 and wait for 0x55 response
    luup.io.intercept()

    if (luup.io.write(string.char(0x00)) == false) then
        log("sendX10Command: Fail to send 0x00 ack byte", 50)
        return 2, nil
    end

    recvd_data = luup.io.read()

    if (recvd_data == nil) then -- timeout
        log("sendX10Command: read() nil received instead of 0x55 response", 50)
        return 2, nil
    end

    if (string.len(recvd_data) > 1) then
        log("sendX10Command: received too many bytes (>1) for inteface ready", 50)
        return 2, nil
    end

    recvd_byte = string.byte(recvd_data, 1, 1)
    recvd_byte = tonumber(recvd_byte)

    if (recvd_byte ~= 0x55) then
        log("sendX10Command: bad interface ready byte. Got " .. string.foramt("0x%X", recvd_byte) .. ", expected 0x55")
        -- ignore error since we are done
    end

    log("sendX10Command: Job finished successfully")

    return 4, nil
end

---------------------------
-- Handle Incoming Data: --
---------------------------
function incoming(lul_data)

    -- This prevents getting stuck. If the buffer is bigger than 18 (9 bytes and blank spaces between them), resets variable to start again
    -- It is not elegant, but effective. The CM11 is not the best interface.

    -- get incoming buffer
    local buffer_CM11 = luup.variable_get(CM11_SID, "Incoming_CM11_buffer", controller_id)
    if (string.len (buffer_CM11) > 18 ) then
        init_polling ('1')
        luup.sleep(1000)
        return
    end

    -- get polling status 0 = no polling, 1 = polling
    local polling = luup.variable_get(CM11_SID, "Polling_status", controller_id)

    -- process incoming data
    local data_raw = string.byte (lul_data,1)
    local data_hex = string.format ("%X",tonumber(data_raw))
    local command
    local no_of_bytes
    local no_of_bytes_raw
    local counter_of_bytes
    local counter_of_bytes_raw

    if (polling == "0" and data_hex =="5A") then -- polling request from CM11
        -- Command from Vera to CM11 to get buffer
        command = string.char(0xC3)
        sendCommand_direct_x10(command)

        -- Reset internal variables
        -- buffer
        luup.variable_set(CM11_SID, "Incoming_CM11_buffer","", controller_id)
        -- polling status
        luup.variable_set(CM11_SID, "Polling_status","1", controller_id)
        -- no of bytes to process
        luup.variable_set(CM11_SID, "Buffer_CM11_no_bytes","0", controller_id)
        luup.variable_set(CM11_SID, "Processed_bytes","0", controller_id)

    elseif (polling == "0" and data_hex =="A5") then  -- power failure
		-- Set time command to restore internal clock.
		-- At this time a fake time/date is sent only to recover unit as no macros are running in CM11 ( I prefer Vera to control macros)
		--	02/05/2013 18:57:06 : Sent via serial: 9B
		--	02/05/2013 18:57:06 : Sent via serial: 6, 75, 8, 79, 10, 60
        command = string.char(0x9B)
        sendCommand_direct_x10(command)
        command = string.char(0x6 .. 0x75 .. 0x8 .. 0x79 .. 0x10 .. 0x60)
        sendCommand_direct_x10(command)

    elseif (polling == "1") then

        buffer_CM11 = (buffer_CM11 .. data_hex .. ' ')
        luup.variable_set(CM11_SID, "Incoming_CM11_buffer",buffer_CM11, controller_id)

        -- Set number of bytes for the first time
        no_of_bytes_raw = luup.variable_get(CM11_SID, "Buffer_CM11_no_bytes", controller_id)
        no_of_bytes = tonumber (no_of_bytes_raw)
        if  (no_of_bytes == 0) then
            no_of_bytes = tonumber (data_hex,16)
            -- Set number of bytes
            luup.variable_set(CM11_SID, "Buffer_CM11_no_bytes",tostring(no_of_bytes), controller_id)
            luup.variable_set(CM11_SID, "Processed_bytes","0", controller_id)
        end

        -- Look how many bytes have been processed/stored from the CM11 buffer
        counter_of_bytes_raw = luup.variable_get(CM11_SID, "Processed_bytes", controller_id)
        counter_of_bytes = tonumber(counter_of_bytes_raw)

        if (counter_of_bytes < no_of_bytes) then -- Building from CM11 buffer.
            counter_of_bytes = counter_of_bytes + 1
            luup.variable_set(CM11_SID, "Processed_bytes",tostring(counter_of_bytes), controller_id)

        elseif (counter_of_bytes == no_of_bytes) then -- Building finished.
            -- reset polling status. initialize variables
            init_polling ('1')

            -- Decode buffer
            decode_buffer_x10(buffer_CM11)

        else
        end
    end
 end

function init_polling (request)

    -- single byte read - incoming data
    if request == '1' then
        -- Reset/init internal variables
        -- buffer
        luup.variable_set(CM11_SID, "Incoming_CM11_buffer","", controller_id)
        -- polling status
        luup.variable_set(CM11_SID, "Polling_status","0", controller_id)
        -- no of bytes to process
        luup.variable_set(CM11_SID, "Buffer_CM11_no_bytes","0", controller_id)
        luup.variable_set(CM11_SID, "Processed_bytes","0", controller_id)
    end
 end

function x10_log(x10_type_name, log_text, level)
      if (level == nil) then
        level = 50
      end

      if (x10_type_name == nil) then
        x10_type_name = "Unknown"
      end

      if (log_text == nil) then
        log_text = "nil log text"
      end

      luup.log(x10_type_name .. ": " .. log_text, level)
end

function switch_set_target(lul_device, lul_settings)
    local lul_command = 'Off'
    lul_device = tonumber(lul_device)
    local lul_reverse = luup.variable_get(HADEVICE_SID, "ReverseOnOff", lul_device)
    local myTypeName = luup.devices[lul_device].description
    local myX10id = x10_id(luup.devices[lul_device].id)
    local myDevicePrefix = x10_type(luup.devices[lul_device].id)
    local action_settings = {}

      if(lul_settings.newTargetValue == "1" or (lul_settings.newTargetValue == "0" and lul_reverse == "1")) then
        lul_command = 'On'
      end

      if(myDevicePrefix == "H-") then
        lul_command = 'All Lights Off'
        if(lul_settings.newTargetValue == "1" or (lul_settings.newTargetValue == "0" and lul_reverse == "1")) then
          lul_command = 'All Lights On'
        end
      end

      luup.variable_set(x10_type_name, "pendingNewState", lul_settings.newTargetValue, lul_device)
      local cmd_settings = {["x10_id"] = myX10id, ["command"] = lul_command, ["data"] = ""}

      x10_log(myTypeName, "switch_set_target: Calling action SendX10Command, " .. cmd_settings["x10_id"] .. ", " .. cmd_settings["command"] .. ", " .. cmd_settings["data"])
      local jobStatus, notes = sendX10Command(cmd_settings)

      if(notes == nil) then
        notes = ""
      end
      -- see if the command executed immediately
      if (jobStatus == 4 ) then
        x10_log(myTypeName, "switch_set_target: action appears to have completed successfully")
        action_settings["function"] = lul_command
        manage_actions(myX10id, action_settings)
      elseif (jobStatus == 2) then
        x10_log(myTypeName, "switch_set_target: job returned error (2), notes = " .. notes)
      elseif (jobStatus == 3) then
        x10_log(myTypeName, "switch_set_target: job returned abort (3)")
      elseif (jobStatus == -1) then
        x10_log(myTypeName, "switch_set_target: job returned no job (-1)")
      else
        x10_log(myTypeName, "switch_set_target: unknown error: " .. tostring(jobStatus) .. "and notes: " .. notes)
      end
end

local function GetX10DimCommand(myTypeName, myX10id, cur_status, newTarget)
    local command = ""
    local dataval = ""

    x10_log(myTypeName, "GetX10DimCommand: cur_status = " .. tostring(cur_status) .. ", newTarget = " .. tonumber(newTarget))

    if(newTarget == 0) then
        command = 'Off'
    elseif(is_type(myX10id, "SoftStartModules")) then
        local dim_level = math.floor(newTarget * 63/100)
        command = 'EXT'
        dataval = tostring(dim_level)
    else
        -- For PL commands we can send a target dim level:
        -- Older x10 modules use "dim" and scale from 0 to 31.
        local current_dim_level = math.floor(cur_status * 22/100)
        local dim_level = math.floor(newTarget *22/100) -- 22 X10 protocol for DIM

        -- if the current level is less than the new level, we need to send BRIGHT commands.
        -- otherwise, we send DIM commands for the difference.
        local dim_change = 0

        -- these modules usually come on at full brightness if the user just clicks the "on" button.
        -- if our current level is zero (off) and the new level is 100, then don't send any dimming
        -- commands

        if (cur_status == 0 and newTarget == 100) then
          command = 'On'
        elseif (dim_level > current_dim_level) then
          dim_change = dim_level - current_dim_level;
          command = 'Bright'
          dataval = tostring(dim_change)
        elseif(dim_level < current_dim_level) then
          dim_change = current_dim_level - dim_level
          command = 'Dim'
          dataval = tostring(dim_change)
        end
    end

    x10_log(myTypeName, "GetX10DimCommand: command = " .. command .. ", dataval = " .. dataval)
    return command, dataval
end

function set_dim_level(lul_device, lul_settings)
    lul_device = tonumber(lul_device)
    local cur_status = luup.variable_get(DIMMING_SID, "LoadLevelStatus", lul_device)
    local newTargetValue = lul_settings.newLoadlevelTarget
    local myTypeName = luup.devices[lul_device].description
    local myX10id = x10_id(luup.devices[lul_device].id)
    local action_settings = {}

      if (cur_status) then
        cur_status = tonumber(cur_status)
      else
        cur_status = 0
      end

      local command, dataval = GetX10DimCommand(myTypeName, myX10id, cur_status, tonumber(newTargetValue))

      local cmd_settings = {["x10_id"] = myX10id, ["command"] = command, ["data"] = dataval}

      x10_log(myTypeName, "set_dim_level: Calling action SendX10Command, " .. cmd_settings["x10_id"] .. ", " .. cmd_settings["command"] .. ", " .. cmd_settings["data"])
      local jobStatus, notes = sendX10Command(cmd_settings)

      if(notes == nil) then
        notes = ""
      end
      -- see if the command executed immediately
      if (jobStatus == 4 ) then
        x10_log(myTypeName, "set_dim_level: action appears to have completed successfully")
        action_settings["function"] = command
        action_settings["functionData"] = newTargetValue
        manage_actions(myX10id, action_settings)
      elseif (jobStatus == 2) then
        x10_log(myTypeName, "set_dim_level: job returned error (2), notes = " .. notes)
      elseif (jobStatus == 3) then
        x10_log(myTypeName, "set_dim_level: job returned abort (3)")
      elseif (jobStatus == -1) then
        x10_log(myTypeName, "set_dim_level: job returned no job (-1)")
      else
        x10_log(myTypeName, "set_dim_level: unknown error: " .. tostring(jobStatus) .. "and notes: " .. notes)
      end
end
