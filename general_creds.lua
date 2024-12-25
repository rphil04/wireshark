-- General Credential Detector Protocol
cred_proto = Proto("credentials", "Credential Detector")

-- Define protocol fields
local fields = {
    username = ProtoField.string("credentials.username", "Username"),
    password = ProtoField.string("credentials.password", "Password"),
    info = ProtoField.string("credentials.info", "Info")
}

cred_proto.fields = fields

-- Helper function to extract credentials
local function extract_credentials(buffer, pattern)
    local creds = buffer():string():match(pattern)
    return creds
end

-- Dissector function
function cred_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end

    pinfo.cols.protocol = "Cred-Detector"
    local subtree = tree:add(cred_proto, buffer(), "Credential Data")

    -- HTTP Basic Auth
    local http_creds = extract_credentials(buffer, "Authorization: Basic ([A-Za-z0-9+/=]+)")
    if http_creds then
        subtree:add(fields.info, "HTTP Basic Authorization Detected")
        subtree:add(fields.username, "Encoded: " .. http_creds)
    end

    -- FTP Credentials
    local ftp_user = extract_credentials(buffer, "USER%s+([%w%d]+)")
    local ftp_pass = extract_credentials(buffer, "PASS%s+([%w%d]+)")
    if ftp_user then subtree:add(fields.username, ftp_user) end
    if ftp_pass then subtree:add(fields.password, ftp_pass) end

    -- Telnet Credentials
    local telnet_creds = extract_credentials(buffer, "login:%s*([%w%d]+)%s+password:%s*([%w%d]+)")
    if telnet_creds then
        subtree:add(fields.info, "Telnet Credentials Detected")
        subtree:add(fields.username, "Extracted: " .. telnet_creds)
    end
end

-- Register dissector for relevant ports
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(21, cred_proto) -- FTP
tcp_table:add(23, cred_proto) -- Telnet
tcp_table:add(80, cred_proto) -- HTTP
tcp_table:add(8080, cred_proto) -- HTTP Alternate
