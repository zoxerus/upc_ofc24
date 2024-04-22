
#ifndef __EGRESS__
#define __EGRESS__

/* The Egress Control Block */
control egress(inout headers hdr,
               inout metadata meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{

    /*
    IMPORTANT: 
    I am using this behaviour because of these two facts:

    For CE2E packets, packet_in is from the egress packet that 
    caused this clone to be created. It starts with the headers emitted by
    the egress deparser, followed by the payload of that packet, 
    i.e. the part that was not parsed by the egress parser.
    Truncation of the payload is supported.

    For CI2E packets, packet_in is from the ingress packet that 
    caused this clone to be created. It is the same as the 
    pre-IngressParser contents of packet_in of that ingress packet, 
    with no modifications from any ingress processing. 
    Truncation of the payload is supported.
    */

    action insert_md(){
        hdr.int_md.delay =  (bit<64>) istd.egress_timestamp - hdr.int_md.delay;
        // hdr.ethernet.dstMac = 0xb83fd29f117a;
        // ostd.clone = true;
        // ostd.clone_session_id = (CloneSessionId_t) 16w500; 
    }


    action insert_md_and_clone(bit<16> clone_session){
        ostd.clone = true;
        ostd.clone_session_id = (CloneSessionId_t) clone_session; 
    }
    table tbl_int{
        key = {
            istd.egress_port    : exact;
        }
        actions = { 
            NoAction; insert_md; just_clone;
        } 
        default_action = NoAction;
    }

    apply {
        if (istd.packet_path == PSA_PacketPath_t.CLONE_E2E ){
            hdr.int_md.setInvalid();
            hdr.ipv4.totallen = hdr.ipv4.totallen - INT_MD_LEN_BYTES; 
            hdr.udp.length = hdr.udp.length - INT_MD_LEN_BYTES;
        } else {
            tbl_int.apply();
            
        }

     }

} // end of egress


#endif // __EGRESS__