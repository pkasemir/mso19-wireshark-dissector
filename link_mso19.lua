-- vim: set expandtab ts=4 sw=4:
mso19 = Proto("LINK_mso19",  "Link MSO19")

local cmd_wrapper = 0x7e
local current_bank

local State = { begin = 0, body = 1 }

MsoCtx = { }
function MsoCtx:reset()
    self.infos = { [0] = { bank = 0, state = State.begin }}
    self.last = 0
end
function MsoCtx:prepare_info(pinfo)
    local info = self.infos[pinfo.number]
    if info == nil then
        info = { }
        self.infos[pinfo.number] = info
        info.prev = self.infos[self.last]
        self.last = pinfo.number
    end

    info.bank = info.prev.bank
    info.state = info.prev.state
end
function MsoCtx:current_bank(pinfo)
    return self.infos[pinfo.number].bank
end
function MsoCtx:update_bank(pinfo, bank)
    self.infos[pinfo.number].bank = bank
end

function MsoCtx:current_state(pinfo)
    return self.infos[pinfo.number].state
end
function MsoCtx:update_state(pinfo, state)
    self.infos[pinfo.number].state = state
end
    
local header   = ProtoField.bytes("mso19.header", "Header")
local tailer   = ProtoField.bytes("mso19.tailer", "Tailer")
local command   = ProtoField.bytes("mso19.command", "Command")
local response = ProtoField.bytes("mso19.response", "Response")

mso19.fields = { header, tailer, command, response }

function check_magic(buffer)
    local length = buffer:len()
    if length < 5 then return false end
    local magic = 0x404c4453
    return buffer(0, 4):uint() == magic and buffer(4, 1):uint() == cmd_wrapper
end

function dissect_control(buffer, pinfo, tree)
    local length = buffer:len()
    local command_buffer

    if MsoCtx:current_state(pinfo) == State.begin then
        if not check_magic(buffer) then return 0 end
        tree:add(header, buffer(0, 5))
        MsoCtx:update_state(pinfo, State.body)
        if length == 5 then return buffer:offset() + 5 end
        command_buffer = buffer(5)
    else
        command_buffer = buffer
    end
    local bank, addr, value, tmp
    while command_buffer:len() >= 1 do
        if command_buffer(0, 1):uint() == cmd_wrapper then
            tree:add(tailer, command_buffer(0, 1))
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
        tree:add(command, command_buffer(0, 2)):set_text(string.format(
            " Bank %s Addr: %2d value: 0x%02x",
            bank, addr, value))
        -- Avoid out of range error when trying to consume the entire tvb
        if command_buffer:len() == 2 then return command_buffer:offset() + 2 end
        command_buffer = command_buffer(2)
    end
    return command_buffer:offset()

end

function mso19.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = mso19.name

    local subtree = tree:add(mso19, buffer(), "USB MSO19")
    MsoCtx:prepare_info(pinfo)

    local control_found = false
    local offset = 0
    local control_buffer = buffer
    while offset < length do
        offset = dissect_control(buffer(offset), pinfo, subtree)
        if offset == 0 then break end
        control_found = true
    end

    if not control_found then
        subtree:add(response, buffer())
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
