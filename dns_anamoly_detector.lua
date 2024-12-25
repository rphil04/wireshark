-- Declare DNS Anomaly Detector Protocol
dns_proto = Proto("dns_anomaly", "DNS Anomaly Detector")

-- Define protocol fields
local fields = {
    query_name = ProtoField.string("dns_anomaly.query_name", "Query Name"),
    query_type = ProtoField.string("dns_anomaly.query_type", "Query Type"),
    warning = ProtoField.string("dns_anomaly.warning", "Warning")
}

dns_proto.fields = fields

-- Dissector function
function dns_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end

    pinfo.cols.protocol = "DNS-Anomaly"
    local subtree = tree:add(dns_proto, buffer(), "DNS Anomaly Detection")

    local query_name = buffer():string():match("(%w[%w%.%-]+)%.%s")
    local query_type = buffer():string():match("(%w+)%sQUERY")

    if query_name then
        subtree:add(fields.query_name, query_name)
    end
    if query_type then
        subtree:add(fields.query_type, query_type)
    end

    -- Check for anomalies
    if query_name and #query_name > 253 then
        subtree:add(fields.warning, "Suspicious: Domain name exceeds 253 characters")
    elseif query_name and query_name:find("%.onion") then
        subtree:add(fields.warning, "Suspicious: Query to .onion domain")
    end
end

-- Register dissector for DNS traffic
local udp_table = DissectorTable.get("udp.port")
udp_table:add(53, dns_proto)
