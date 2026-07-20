-- Thread Alternate PHY (HDR): MLE TLV 91, Connectivity APS0, DAPS (MAC cmd 0x34).
-- Install: ~/.local/lib/wireshark/plugins/ then Ctrl+Shift+L.

local ALT_PHY_CAP_TLV_TYPE = 91
local PHY_ID_TL3_GFSK      = 0

local THREAD_MAC_CMD_ID = 0x34
local DAPS_SUB_ID       = 0x00

local SUBTLV_LEN_TL3_GFSK = 5
local SUBTLV_LEN_TL3_GFSK_LEGACY = 3

local PHY_ID_NAMES = {
    [PHY_ID_TL3_GFSK] = "TL3 2 Mbps GFSK",
}

local p_altphy = Proto("thread_altphy", "Thread Alternate PHY (HDR)")

local f_subtlv_phyid  = ProtoField.uint8("thread_altphy.subtlv.phy_id", "PHY ID", base.DEC, PHY_ID_NAMES)
local f_subtlv_len    = ProtoField.uint8("thread_altphy.subtlv.len", "Length", base.DEC)
local f_gfsk_flags    = ProtoField.uint8("thread_altphy.gfsk.flags", "Flags", base.HEX)
local f_gfsk_cl       = ProtoField.uint8("thread_altphy.gfsk.concurrent_listening",
                                         "Concurrent Listening", base.DEC,
                                         { [0] = "No", [1] = "Yes" }, 0x01)
local f_gfsk_reserved = ProtoField.uint8("thread_altphy.gfsk.flags.reserved", "Reserved", base.HEX, nil, 0xFE)
local f_gfsk_settling = ProtoField.uint8("thread_altphy.gfsk.settling_delay", "TL3_SETTLING_DELAY (us)", base.DEC)
local f_gfsk_aifs     = ProtoField.uint8("thread_altphy.gfsk.aifs", "TL3_AIFS (us)", base.DEC)
local f_gfsk_max_psdu = ProtoField.uint16("thread_altphy.gfsk.max_psdu",
                                         "TL3_MAX_PSDU (octets, incl. FCS)", base.DEC)
local f_daps_cmd      = ProtoField.uint8("thread_altphy.daps.command_id", "Thread MAC Command ID", base.HEX)
local f_daps_subid    = ProtoField.uint8("thread_altphy.daps.sub_id", "DAPS Sub-ID", base.HEX)
local f_daps_phyid    = ProtoField.uint8("thread_altphy.daps.phy_id", "PHY ID", base.DEC, PHY_ID_NAMES)
local f_daps_channel  = ProtoField.uint8("thread_altphy.daps.channel", "Channel", base.DEC)
local f_conn_aps0     = ProtoField.uint8("thread_altphy.conn.aps0",
                                         "APS0 (Alternate PHY Support, PHY ID 0)", base.DEC,
                                         { [0] = "Not supported", [1] = "Supported" }, 0x01)

p_altphy.fields = {
    f_subtlv_phyid, f_subtlv_len,
    f_gfsk_flags, f_gfsk_cl, f_gfsk_reserved,
    f_gfsk_settling, f_gfsk_aifs, f_gfsk_max_psdu,
    f_daps_cmd, f_daps_subid, f_daps_phyid, f_daps_channel,
    f_conn_aps0,
}

local mle_tlv_type     = Field.new("mle.tlv.type")
local mle_tlv_unknown  = Field.new("mle.tlv.unknown")
local mle_conn_flags   = Field.new("mle.tlv.conn.flags")
local wpan_cmd         = Field.new("wpan.cmd")
local wpan_unknown_cmd = Field.new("wpan.cmd.unknown_cmd")
local wpan_fcf         = Field.new("wpan.fcf")

local WPAN_FRAME_TYPE_MAC_COMMAND = 3

local function band(a, b)
    if bit32 ~= nil then
        return bit32.band(a, b)
    end
    if bit ~= nil then
        return bit.band(a, b)
    end
    return a & b
end

local function rshift(a, n)
    if bit32 ~= nil then
        return bit32.rshift(a, n)
    end
    if bit ~= nil then
        return bit.rshift(a, n)
    end
    return a >> n
end

local function add_gfsk_value_current(subtree, vrange)
    local n = vrange:len()
    if n >= 1 then
        subtree:add(f_gfsk_flags, vrange:range(0, 1))
        subtree:add(f_gfsk_cl, vrange:range(0, 1))
        subtree:add(f_gfsk_reserved, vrange:range(0, 1))
    end
    if n >= 2 then subtree:add(f_gfsk_settling, vrange:range(1, 1)) end
    if n >= 3 then subtree:add(f_gfsk_aifs, vrange:range(2, 1)) end
    if n >= 5 then subtree:add_le(f_gfsk_max_psdu, vrange:range(3, 2)) end
end

local function add_gfsk_value_legacy(subtree, vrange)
    local n = vrange:len()
    if n >= 1 then subtree:add(f_gfsk_settling, vrange:range(0, 1)) end
    if n >= 2 then subtree:add(f_gfsk_aifs, vrange:range(1, 1)) end
    if n >= 3 then
        subtree:add(f_gfsk_flags, vrange:range(2, 1))
        subtree:add(f_gfsk_cl, vrange:range(2, 1))
        subtree:add(f_gfsk_reserved, vrange:range(2, 1))
    end
end

local function add_gfsk_value(subtree, vrange, sub_len)
    if sub_len == SUBTLV_LEN_TL3_GFSK then
        add_gfsk_value_current(subtree, vrange)
    elseif sub_len == SUBTLV_LEN_TL3_GFSK_LEGACY then
        local st = subtree:add(p_altphy, vrange, "Legacy sub-TLV layout (settling, AIFS, flags)")
        add_gfsk_value_legacy(st, vrange)
    else
        subtree:add_expert_info(PI_MALFORMED, PI_WARN,
            string.format("TL3 GFSK sub-TLV length should be %d (got %d)",
                          SUBTLV_LEN_TL3_GFSK, sub_len))
        if sub_len > 0 then
            add_gfsk_value_current(subtree, vrange)
        end
    end
end

local function dissect_alt_phy_cap(tree, vrange)
    local subtree = tree:add(p_altphy, vrange, "Alternate PHY Capability TLV (type 91)")
    local total   = vrange:len()
    local pos     = 0

    while pos + 2 <= total do
        local phy_id  = vrange:range(pos, 1):uint()
        local sub_len = vrange:range(pos + 1, 1):uint()

        if pos + 2 + sub_len > total then
            subtree:add_expert_info(PI_MALFORMED, PI_WARN, "Truncated Alternate PHY sub-TLV")
            break
        end

        local name = PHY_ID_NAMES[phy_id] or string.format("PHY ID %d", phy_id)
        local st = subtree:add(p_altphy, vrange:range(pos, 2 + sub_len),
                               "Alternate PHY Sub-TLV: " .. name)
        st:add(f_subtlv_phyid, vrange:range(pos, 1))
        st:add(f_subtlv_len, vrange:range(pos + 1, 1))

        if sub_len > 0 then
            local vr = vrange:range(pos + 2, sub_len)
            if phy_id == PHY_ID_TL3_GFSK then
                add_gfsk_value(st, vr, sub_len)
            end
        end

        pos = pos + 2 + sub_len
    end
end

local function dissect_daps_payload(subtree, payload_range)
    local total = payload_range:len()
    if total < 1 then
        return
    end

    local sub_id = payload_range:range(0, 1):uint()
    subtree:add(f_daps_subid, payload_range:range(0, 1))

    if sub_id ~= DAPS_SUB_ID then
        subtree:add_expert_info(PI_PROTOCOL, PI_WARN,
            string.format("Expected DAPS Sub-ID 0x%02X", DAPS_SUB_ID))
        return
    end

    if total >= 2 then
        subtree:add(f_daps_phyid, payload_range:range(1, 1))
    end
    if total >= 3 then
        subtree:add(f_daps_channel, payload_range:range(2, 1))
    end
end

local function dissect_daps_at(tree, tvb, cmd_offset)
    if cmd_offset + 1 >= tvb:len() then
        return
    end

    local daps_len = math.min(tvb:len() - (cmd_offset + 1), 3)
    if daps_len < 1 then
        return
    end

    local st = tree:add(p_altphy, tvb:range(cmd_offset, 1 + daps_len),
                        "Thread MAC Command: DAPS (0x34)")
    st:add(f_daps_cmd, tvb:range(cmd_offset, 1))
    dissect_daps_payload(st, tvb:range(cmd_offset + 1, daps_len))
end

local function resolve_daps_cmd_offset(tvb, hint_offset)
    if hint_offset == nil then
        return nil
    end

    for delta = 0, 2 do
        local off = hint_offset - delta
        if off >= 0 and off + 1 < tvb:len() then
            if tvb:range(off, 1):uint() == THREAD_MAC_CMD_ID
               and tvb:range(off + 1, 1):uint() == DAPS_SUB_ID then
                return off
            end
        end
    end

    return nil
end

local function mac_command_payload_offset(mac_range, include_seq)
    if mac_range:len() < 3 then
        return nil
    end

    local fcf = mac_range:range(0, 2):le_uint()
    if band(fcf, 0x7) ~= WPAN_FRAME_TYPE_MAC_COMMAND then
        return nil
    end

    local pos = 2
    if include_seq then
        pos = pos + 1
    end

    local dest_mode = band(rshift(fcf, 10), 0x3)
    local src_mode  = band(rshift(fcf, 14), 0x3)
    local pan_comp  = band(rshift(fcf, 6), 0x1)

    if dest_mode == 2 or dest_mode == 3 then
        if pan_comp == 0 or src_mode == 0 then
            pos = pos + 2
        end
    end

    if dest_mode == 2 then
        pos = pos + 2
    elseif dest_mode == 3 then
        pos = pos + 8
    end

    if src_mode == 2 or src_mode == 3 then
        if pan_comp == 0 or dest_mode == 0 then
            pos = pos + 2
        end
    end

    if src_mode == 2 then
        pos = pos + 2
    elseif src_mode == 3 then
        pos = pos + 8
    end

    return pos
end

local function is_daps_command_at(mac_range, payload_offset)
    if payload_offset == nil then
        return false
    end
    if payload_offset + 1 >= mac_range:len() then
        return false
    end
    return mac_range:range(payload_offset, 1):uint() == THREAD_MAC_CMD_ID
       and mac_range:range(payload_offset + 1, 1):uint() == DAPS_SUB_ID
end

local function find_daps_in_mac_range(mac_range, mac_offset)
    if mac_range:len() >= 2 then
        local fcf = mac_range:range(0, 2):le_uint()
        if band(fcf, 0x7) ~= WPAN_FRAME_TYPE_MAC_COMMAND then
            return nil
        end
    end

    for _, include_seq in ipairs({ false, true }) do
        local payload_offset = mac_command_payload_offset(mac_range, include_seq)
        if is_daps_command_at(mac_range, payload_offset) then
            return mac_offset + payload_offset
        end
    end

    -- Nordic sniffer captures include dest PAN even when PAN compression is set.
    do
        local payload_offset = mac_command_payload_offset(mac_range, false)
        if payload_offset ~= nil then
            payload_offset = payload_offset + 2
            if is_daps_command_at(mac_range, payload_offset) then
                return mac_offset + payload_offset
            end
        end
    end

    for pos = 0, mac_range:len() - 2 do
        if is_daps_command_at(mac_range, pos) then
            return mac_offset + pos
        end
    end

    return nil
end

local function mac_range_for_packet(tvb)
    local fcf = wpan_fcf()
    if fcf ~= nil then
        local mac_offset = fcf.offset
        return mac_offset, tvb:range(mac_offset, tvb:len() - mac_offset)
    end

    if tvb:len() >= 4 then
        local tap_len = tvb:range(2, 2):le_uint()
        if tap_len >= 4 and tap_len < tvb:len() then
            return tap_len, tvb:range(tap_len, tvb:len() - tap_len)
        end
    end

    return nil, nil
end

local function is_mac_command_packet(tvb)
    local cmd = wpan_cmd()
    if cmd ~= nil and tonumber(cmd.value) == THREAD_MAC_CMD_ID then
        return true
    end

    local fcf = wpan_fcf()
    if fcf ~= nil and band(tonumber(fcf.value), 0x7) == WPAN_FRAME_TYPE_MAC_COMMAND then
        return true
    end

    local mac_offset, mac_range = mac_range_for_packet(tvb)
    if mac_range ~= nil and mac_range:len() >= 2 then
        return band(mac_range:range(0, 2):le_uint(), 0x7) == WPAN_FRAME_TYPE_MAC_COMMAND
    end

    return false
end

local function find_daps_cmd_offset(tvb)
    local cmd = wpan_cmd()
    if cmd ~= nil and tonumber(cmd.value) == THREAD_MAC_CMD_ID then
        if cmd.offset + 1 < tvb:len()
           and tvb:range(cmd.offset, 1):uint() == THREAD_MAC_CMD_ID
           and tvb:range(cmd.offset + 1, 1):uint() == DAPS_SUB_ID then
            return cmd.offset
        end
        local off = resolve_daps_cmd_offset(tvb, cmd.offset)
        if off ~= nil then
            return off
        end
    end

    local expert = wpan_unknown_cmd()
    if expert ~= nil then
        local off = resolve_daps_cmd_offset(tvb, expert.offset)
        if off ~= nil then
            return off
        end
    end

    local mac_offset, mac_range = mac_range_for_packet(tvb)
    if mac_range ~= nil then
        local off = find_daps_in_mac_range(mac_range, mac_offset)
        if off ~= nil then
            return off
        end
    end

    if is_mac_command_packet(tvb) then
        for off = 0, tvb:len() - 2 do
            if tvb:range(off, 1):uint() == THREAD_MAC_CMD_ID
               and tvb:range(off + 1, 1):uint() == DAPS_SUB_ID then
                return off
            end
        end
    end

    return nil
end

local function dissect_daps(tree, tvb, pinfo)
    local cmd_offset = find_daps_cmd_offset(tvb)
    if cmd_offset == nil then
        return
    end

    dissect_daps_at(tree, tvb, cmd_offset)
    pinfo.cols.info = tostring(pinfo.cols.info) .. " [DAPS]"
end

local function dissect_mle(tree)
    local types = { mle_tlv_type() }
    if types[1] == nil then
        return
    end

    local unknowns = { mle_tlv_unknown() }
    for _, u in ipairs(unknowns) do
        if u == nil then
            break
        end
        local best = nil
        for _, t in ipairs(types) do
            if t.offset < u.offset and (best == nil or t.offset > best.offset) then
                best = t
            end
        end
        if best ~= nil and best.value == ALT_PHY_CAP_TLV_TYPE then
            dissect_alt_phy_cap(tree, u.range)
        end
    end

    local conn = mle_conn_flags()
    if conn ~= nil then
        local subtree = tree:add(p_altphy, conn.range, "Alternate PHY: Connectivity flags")
        subtree:add(f_conn_aps0, conn.range)
    end
end

function p_altphy.dissector(tvb, pinfo, tree)
    dissect_mle(tree)
    dissect_daps(tree, tvb, pinfo)
end

register_postdissector(p_altphy)
