-- Declare Bandwidth Monitor Protocol
bw_proto = Proto("bw_monitor", "Bandwidth Usage Monitor")

-- Define protocol fields
local fields = {
    source_ip = ProtoField.string("bw_monitor.source_ip", "Source IP"),
    total_bytes = ProtoField.uint32("bw_monitor.total_bytes", "Total Bytes")
}

bw_proto.fields = fields

-- Table to store per-IP bandwidth usage
local ip_bandwidth = {}

-- Dissector function
function bw_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end

    pinfo.cols.protocol = "BW-Monitor"
    local src_ip = tostring(pinfo.src)

    -- Track bandwidth
    ip_bandwidth[src_ip] = (ip_bandwidth[src_ip] or 0) + buffer:len()

    -- Create subtree
    local subtree = tree:add(bw_proto, buffer(), "Bandwidth Usage")
    subtree:add(fields.source_ip, src_ip)
    subtree:add(fields.total_bytes, ip_bandwidth[src_ip])
end

-- Register dissector for all TCP traffic
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add_for_decode_as(bw_proto)
