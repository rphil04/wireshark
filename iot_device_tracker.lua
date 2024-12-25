-- Declare IoT Device Tracker Protocol
iot_proto = Proto("iot_tracker", "IoT Device Tracker")

-- Define protocol fields
local fields = {
    device_ip = ProtoField.string("iot_tracker.device_ip", "Device IP"),
    message_type = ProtoField.string("iot_tracker.message_type", "Message Type"),
    warning = ProtoField.string("iot_tracker.warning", "Warning")
}

iot_proto.fields = fields

-- Dissector function
function iot_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end

    pinfo.cols.protocol = "IoT-Tracker"
    local subtree = tree:add(iot_proto, buffer(), "IoT Device Monitoring")

    if pinfo.src:match("^192%.168%.") or pinfo.src:match("^10%.") then
        subtree:add(fields.device_ip, tostring(pinfo.src))
        local message = buffer():string()
        if message:find("unauthorized") then
            subtree:add(fields.warning, "Unauthorized request detected")
        end
    end
end

-- Register dissector for MQTT (port 1883)
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(1883, iot_proto)
