-- Declare Packet Loss Tracker Protocol
packet_loss_proto = Proto("packet_loss", "Packet Loss Tracker")

-- Define protocol fields
local fields = {
    seq_number = ProtoField.uint32("packet_loss.seq_number", "Sequence Number"),
    loss_detected = ProtoField.string("packet_loss.loss_detected", "Loss Detected")
}

packet_loss_proto.fields = fields

-- Table to track sequence numbers
local seq_tracker = {}

-- Dissector function
function packet_loss_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end

    pinfo.cols.protocol = "Pkt-Loss"
    local subtree = tree:add(packet_loss_proto, buffer(), "Packet Loss Detection")

    local seq_number = tonumber(buffer(0, 4):uint())
    local stream_id = tostring(pinfo.src) .. "->" .. tostring(pinfo.dst)

    if seq_tracker[stream_id] and seq_tracker[stream_id] + 1 ~= seq_number then
        subtree:add(fields.loss_detected, "Packet loss detected!")
    end

    seq_tracker[stream_id] = seq_number
    subtree:add(fields.seq_number, seq_number)
end

-- Register dissector for TCP traffic
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add_for_decode_as(packet_loss_proto)
