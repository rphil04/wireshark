-- Declare HTTP File Download Tracker
http_file_proto = Proto("http_file", "HTTP File Download Tracker")

-- Define protocol fields
local fields = {
    file_url = ProtoField.string("http_file.url", "File URL"),
    file_type = ProtoField.string("http_file.type", "File Type"),
    client_ip = ProtoField.string("http_file.client_ip", "Client IP")
}

http_file_proto.fields = fields

-- Dissector function
function http_file_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end

    pinfo.cols.protocol = "HTTP-File"
    local subtree = tree:add(http_file_proto, buffer(), "HTTP File Download")

    local url = buffer():string():match("GET%s(/[^%s]+)%s")
    if url then
        subtree:add(fields.file_url, url)
        local file_ext = url:match("%.([a-zA-Z0-9]+)$")
        if file_ext then
            subtree:add(fields.file_type, file_ext)
        end
    end
end

-- Register dissector for HTTP traffic
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(80, http_file_proto)
tcp_table:add(8080, http_file_proto)
