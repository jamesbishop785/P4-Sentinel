#include <core.p4> // P4 Libary
#include <v1model.p4> // BMv2 Reference Switch

// Constants
#define THRESHOLD            100    // PPS Threshold
#define TIME_WINDOW          1      // Time Window (1s)
#define INACTIVITY_TIMEOUT   5      // Reset Counters after 5 secs of Inactivity
#define REGISTER_SIZE        1024   // Number of Entries in Registers

// Headers
header ethernet_t {
    bit<48> dstAddr;    // Destination MAC Address
    bit<48> srcAddr;    // Source MAC Address
    bit<16> etherType;  // Protocol Type
}

// Metadata
struct metadata {
    bit<32> current_count;  // Current Packet Count
    bit<32> last_time;      // Last Packet Time
    bit<32> time_elapsed;   // Time Since Last Packet
    bit<32> calculated_pps; // Calculated PPS
    bool    reset_occurred; // Reset Counter
    bit<32> current_drops;  // Dropped Packet Count
}

// Header Struct
struct headers {
    ethernet_t eth; // Parsed Ethernet Header
}

// Registers
register<bit<32>>(REGISTER_SIZE) packet_counter;    // Stores Forward Packets
register<bit<32>>(REGISTER_SIZE) last_timestamp;    // Stores Last Packet Time
register<bit<32>>(REGISTER_SIZE) drop_counter;      // Stores Dropped Packets

// Parser
parser JamesParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.eth);    // Extracts the Ethernet Header from Packet
        transition accept;          // Next Pipeline Stage (Ingress)
    }
}

// Ingress Processing
control JamesIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

// Drop Packet and Increment Counter   
    action drop_packet(bit<32> index) {
        drop_counter.read(meta.current_drops, index);
        drop_counter.write(index, meta.current_drops + 1);
        mark_to_drop(standard_metadata);
    }

// Packet Forwarding Action
    action forward_packet() {
        standard_metadata.egress_spec = 1; // Output Port 1
    }

    apply {
        // Gets Current Timestamp
        bit<32> current_time = (bit<32>)(standard_metadata.ingress_global_timestamp >> 16);
        
        // Hash source MAC to Determine Register Index (0-1024)
        bit<32> index = (bit<32>)hdr.eth.srcAddr[15:0] % REGISTER_SIZE;
        
        // Read Present Condition
        packet_counter.read(meta.current_count, index); // Reads Number of Packets a Source has Sent
        last_timestamp.read(meta.last_time, index);     // When Packet Last Arrived
        
        // Compute Time Since Last Packet
        meta.time_elapsed = current_time - meta.last_time;
        meta.reset_occurred = false;
        
        // Resets Counts when Packets not been sent for 5s
        if (meta.time_elapsed >= INACTIVITY_TIMEOUT) {
            meta.current_count = 0;
            meta.reset_occurred = true;
            drop_counter.write(index, 0);
        } 
        else if (meta.time_elapsed >= TIME_WINDOW) {
            meta.current_count = 0; // Resets Packet Count to 0 after 1s
        }
        
        // Counter if no Reset Happend
        if (!meta.reset_occurred) {
            meta.current_count = meta.current_count + 1;
        }
        
        // Calculate PPS
        meta.calculated_pps = meta.current_count / TIME_WINDOW;
        
        // Update Counts 
        packet_counter.write(index, meta.current_count);
        last_timestamp.write(index, current_time);
        
        // Packet Rate Limiter - PPS > THRESHOLD (100/pps)
        if (meta.calculated_pps > THRESHOLD) {
            drop_packet(index);
        } else {
            forward_packet();   // Forward Packets if below 100/pps to Port 1
        }
    }
}

// Other Pipeline Stages Empty, But Still Needed to be Declared for BMv2 Switch
control JamesVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }
control JamesEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) { apply { } }
control JamesComputeChecksum(inout headers hdr, inout metadata meta) { apply { } }

// Deparser
control JamesDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
    }
}

// Pipeline
V1Switch(
    JamesParser(),
    JamesVerifyChecksum(),
    JamesIngress(),
    JamesEgress(),
    JamesComputeChecksum(),
    JamesDeparser()
) main;