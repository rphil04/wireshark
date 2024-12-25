-- ICS Credential Detector Protocol
ics_cred_proto = Proto("ics_credentials", "ICS Credential Detector")

-- Define protocol fields
local fields = {
    protocol_name = ProtoField.string("ics_credentials.protocol_name", "Protocol"),
    username = ProtoField.string("ics_credentials.username", "Username"),
    password = ProtoField.string("ics_credentials.password", "Password"),
    info = ProtoField.string("ics_credentials.info", "Info")
}

ics_cred_proto.fields = fields

-- Helper function to extract data based on a pattern
local function extract_data(buffer, pattern)
    return buffer():string():match(pattern)
end

-- Dissector function
function ics_cred_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end

    pinfo.cols.protocol = "ICS-Creds"
    local subtree = tree:add(ics_cred_proto, buffer(), "ICS Credential Data")

    -- Modbus Credentials
    if pinfo.cols.info:find("Modbus") then
        local modbus_creds = extract_data(buffer, "LOGIN%s+([%w%d]+)%s+PASSWORD%s+([%w%d]+)")
        if modbus_creds then
            subtree:add(fields.protocol_name, "Modbus")
            subtree:add(fields.username, modbus_creds)
        end
    end

    -- BACnet Credentials
    if pinfo.cols.info:find("BACnet") then
        local bacnet_creds = extract_data(buffer, "USERNAME:%s*([%w%d]+)%s+PASSWORD:%s*([%w%d]+)")
        if bacnet_creds then
            subtree:add(fields.protocol_name, "BACnet")
            subtree:add(fields.username, bacnet_creds)
        end
    end

    -- DNP3 Credentials
    if pinfo.cols.info:find("DNP3") then
        local dnp3_creds = extract_data(buffer, "USER:%s*([%w%d]+)%s+PASS:%s*([%w%d]+)")
        if dnp3_creds then
            subtree:add(fields.protocol_name, "DNP3")
            subtree:add(fields.username, dnp3_creds)
        end
    end

    -- S7Comm Credentials
    if pinfo.cols.info:find("S7Comm") then
        local s7comm_creds = extract_data(buffer, "USER:%s*([%w%d]+)%s+PASS:%s*([%w%d]+)")
        if s7comm_creds then
            subtree:add(fields.protocol_name, "S7Comm")
            subtree:add(fields.username, s7comm_creds)
        end
    end
end

-- Register dissector for relevant ports
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(502, ics_cred_proto) -- Modbus
tcp_table:add(47808, ics_cred_proto) -- BACnet
tcp_table:add(20000, ics_cred_proto) -- DNP3
tcp_table:add(102, ics_cred_proto) -- S7Comm
