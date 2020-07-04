local sxor_proto = Proto("SXOR",  "Single Byte XOR Decrypt Protocol")
sxor_proto.prefs.key = Pref.string("Decryption key", "", "8-bit XOR key (in hex)")

sxor_proto.fields = {}

function sxor_proto.dissector(tvb, pinfo, tree)
    local length = tvb:len()
    if length == 0 then return end

    local decryption_key = sxor_proto.prefs.key
    if decryption_key == "" then
        decryption_key = 0
    else
        decryption_key = tonumber(decryption_key, 16)
    end

    pinfo.cols.protocol = sxor_proto.name
    local subtree = tree:add(sxor_proto, tvb(), "Raw")

    local enc_data = tvb:raw()
    local dec_data = {}
    for i=1,#enc_data do
        dec_data[i] = string.char(bit32.bxor(enc_data:byte(i), decryption_key))
    end
    local ba = ByteArray.new(table.concat(dec_data), true)
    subtree:add(ba:tvb("Decrypted")(), "Decrypted")
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(18590, sxor_proto)
