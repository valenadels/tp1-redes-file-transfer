
local p_fiubardt = Proto("fiubardt", "RDT GA6")


local command = ProtoField.uint8("fiubardt.command", "Command")
local flags = ProtoField.uint8("fiubardt.flags", "Flags")
local data_length = ProtoField.uint32("fiubardt.data_length", "Data Length")
local file_name = ProtoField.string("fiubardt.file_name", "File Name")
local seq_number = ProtoField.uint32("fiubardt.seq_number", "Sequence Number")
local ack_number = ProtoField.uint32("fiubardt.ack_number", "Acknowledgment Number")
local data = ProtoField.bytes("fiubardt.data", "Data")


p_fiubardt.fields = {command, flags, data_length, file_name, seq_number, ack_number, data}


function p_fiubardt.dissector(buf, pinfo, tree)
    local subtree = tree:add(p_fiubardt, buf())


    subtree:add(command, buf(0, 1))
    subtree:add(flags, buf(1, 1))
    subtree:add(data_length, buf(2, 4))
    subtree:add(file_name, buf(6, 400))
    subtree:add(seq_number, buf(406, 4))
    subtree:add(ack_number, buf(410, 4))
    subtree:add(data, buf(414))


    pinfo.cols.protocol:set("RDT GA6")
end


local udp_port = DissectorTable.get("udp.port")
udp_port:add(8080, p_fiubardt)

