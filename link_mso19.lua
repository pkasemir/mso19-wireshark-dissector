-- vim: set expandtab ts=4 sw=4:
mso19 = Proto("LINK_mso19",  "Link MSO19")

local cmd_wrapper = 0x7e
local current_bank
local sample_buffer_count = 1024
local sample_buffer_size = sample_buffer_count * 3

local State = { begin = 0, body = 1 }

MsoCtx = { }
function MsoCtx:reset()
    -- self.endpoints[<endpoint_key>][<type_key>]
    -- [<type_key>] = { last = N, packets = { [<packet_num>] = { ... } }
    self.endpoints = { }
    self.default_packet = {
        command     = { bank = 0, state = State.begin },
        response    = { },
    }
    for _, def in pairs(self.default_packet) do
        def.number = 0
    end
end

function MsoCtx:get_endpoint_info(type_key, endpoint_addr)
    local endpoint_key = tostring(endpoint_addr)
    local endpoint = self.endpoints[endpoint_key]
    if endpoint == nil then
        endpoint = { }
        self.endpoints[endpoint_key] = endpoint
    end
    local endpoint_info = endpoint[type_key]
    if endpoint_info == nil then
        local default_packet = self.default_packet[type_key]
        if default_packet == nil then
            error("Invalid type_key: " .. type_key)
        end
        endpoint_info = { packets = { [0] = default_packet } }
        endpoint_info.last = endpoint_info.packets[0]
        endpoint[type_key] = endpoint_info
    end

    return endpoint_info
end

function MsoCtx:get_endpoint_packet(pinfo, type_key, endpoint_addr)
    local endpoint_info = self:get_endpoint_info(type_key, endpoint_addr)
    local new_packet = false
    local current = endpoint_info.packets[pinfo.number]
    if current == nil then
        current = {
            number = pinfo.number,
            prev = endpoint_info.last,
        }
        endpoint_info.packets[pinfo.number] = current
        endpoint_info.last = current
        new_packet = true
    end
    return current, new_packet
end

function MsoCtx:get_command_packet(pinfo)
    local current, _ = self:get_endpoint_packet(pinfo, "command", pinfo.dst)
    return current
end

function MsoCtx:reset_command_packet(pinfo)
    local current = self:get_command_packet(pinfo)
    local prev = current.prev
    current.bank = prev.bank
    current.state = prev.state
end

function MsoCtx:current_bank(pinfo)
    return self:get_command_packet(pinfo).bank
end

function MsoCtx:update_bank(pinfo, bank)
    self:get_command_packet(pinfo).bank = bank
end

function MsoCtx:current_state(pinfo)
    return self:get_command_packet(pinfo).state
end

function MsoCtx:update_state(pinfo, state)
    self:get_command_packet(pinfo).state = state
end

function MsoCtx:prepare_endpoint_response(pinfo, buffer)
    local current, new_packet = self:get_endpoint_packet(pinfo, "response", pinfo.src)
    if new_packet and buffer:len() > 1 then
        local prev = current.prev
        local prev_length = 0
        if prev.sample_buffer ~= nil then
            prev_length = prev.sample_buffer:len()
        end
        if prev_length == 0 or prev_length >= sample_buffer_size then
            current.sample_buffer = buffer:bytes()
            -- decode the first packet
            current.decode_this = true
        else
            -- steal the combined samples and add to it
            current.sample_buffer = prev.sample_buffer
            prev.sample_buffer = nil
            current.sample_buffer:append(buffer:bytes())
            -- decode the final sized packet
            current.decode_this = current.sample_buffer:len() >= sample_buffer_size
        end
    end

    return current
end

function MsoCtx:get_sample_buffer(pinfo, buffer)
    local response = self:prepare_endpoint_response(pinfo, buffer)
    if not response.decode_this then
        return nil
    end
    if response.sample_buffer ~= nil then
        buffer = response.sample_buffer:tvb("MSO19 Samples")
    end

    return buffer
end

local fields = {
    header      = ProtoField.bytes("mso19.header", "Header"),
    tailer      = ProtoField.bytes("mso19.tailer", "Tailer"),
    command     = ProtoField.bytes("mso19.command", "Command"),
    response    = ProtoField.bytes("mso19.response", "Response"),
    sample      = ProtoField.bytes("mso19.sample", "Sample"),
}
mso19.fields = fields

function check_magic(buffer)
    local length = buffer:len()
    if length < 5 then return false end
    local magic = 0x404c4453
    return buffer(0, 4):uint() == magic and buffer(4, 1):uint() == cmd_wrapper
end

function dissect_control(buffer, pinfo, tree)
    local length = buffer:len()
    local added_tree = false
    local command_buffer

    if MsoCtx:current_state(pinfo) == State.begin then
        if not check_magic(buffer) then return 0 end
        tree:add(fields.header, buffer(0, 5))
        added_tree = true
        MsoCtx:update_state(pinfo, State.body)
        if length == 5 then return buffer:offset() + 5 end
        command_buffer = buffer(5)
    else
        command_buffer = buffer
    end
    local bank, addr, value, tmp
    while command_buffer:len() >= 1 do
        if command_buffer(0, 1):uint() == cmd_wrapper then
            tree:add(fields.tailer, command_buffer(0, 1))
            added_tree = true
            MsoCtx:update_state(pinfo, State.begin)
            return command_buffer:offset() + 1
        end
        if command_buffer:len() < 2 then break end

        tmp = command_buffer(0, 2):uint()
        addr = bit.band(bit.rshift(tmp, 8), 0xf)
        value  = bit.bor(bit.band(tmp, 0x3f), bit.band(bit.rshift(tmp, 6), 0xc0))

        if addr == 0xf then
            MsoCtx:update_bank(pinfo, bit.band(value, 0x3))
            bank = " "
        else
            bank = tostring(MsoCtx:current_bank(pinfo))
        end
        tree:add(fields.command, command_buffer(0, 2)):set_text(string.format(
            " Bank %s Addr: %2d value: 0x%02x",
            bank, addr, value))
        added_tree = true
        -- Avoid out of range error when trying to consume the entire tvb
        if command_buffer:len() == 2 then return command_buffer:offset() + 2 end
        command_buffer = command_buffer(2)
    end
    if not added_tree then return 0 end
    return command_buffer:offset()

end

function dissect_response(buffer, pinfo, tree)
    local sample_buffer = MsoCtx:get_sample_buffer(pinfo, buffer)
    if sample_buffer == nil then
        tree:add(fields.response, buffer())
        return
    end

    local sample = 0
    while sample_buffer:len() >= 3 do
        local raw = sample_buffer(0, 3):uint()
        local logic = bit.bor(
            bit.lshift(bit.band(raw, 0x00003f), 2),
            bit.rshift(bit.band(raw, 0x003000), 12)
            )
        local analog = bit.bor(
            bit.rshift(bit.band(raw, 0x3f0000), 16),
            bit.rshift(bit.band(raw, 0x000f00), 2)
            )
        tree:add(fields.sample, sample_buffer(0, 3)):set_text(string.format(
            "%d: logic %02x analog %d", sample, logic, analog))
        sample = sample + 1
        if sample_buffer:len() == 3 then return end
        sample_buffer = sample_buffer(3)
    end
end

function mso19.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end
    local from_host = tostring(pinfo.src) == "host"

    pinfo.cols.protocol = mso19.name

    local subtree = tree:add(mso19, buffer(), "USB MSO19")

    local control_found = false
    local offset = 0
    local control_buffer = buffer
    if from_host then
        MsoCtx:reset_command_packet(pinfo)
        while offset < length do
            offset = dissect_control(buffer(offset), pinfo, subtree)
            if offset == 0 then break end
            control_found = true
        end
        if not control_found then
            subtree:add(fields.command, buffer())
        end
    else
        dissect_response(buffer, pinfo, subtree)
    end
end

function mso19.init()
    MsoCtx:reset()
end

DissectorTable.get("usb.bulk"):add(0xff, mso19)
DissectorTable.get("usb.bulk"):add(0xffff, mso19)

function mso19_heur(buffer, pinfo, tree)
    if not check_magic(buffer) then return false end
    mso19.dissector(buffer, pinfo, tree)
    -- usb.bulk conversation doesn't seem to work
    pinfo.conversation = mso19
    return true
end

--mso19:register_heuristic("usb.bulk", mso19_heur)
