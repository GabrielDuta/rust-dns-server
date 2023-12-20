mod byte_packet_buffer;
mod result_code;
mod dns_header;
mod query_type;
mod dns_question;
mod dns_record;
mod dns_packet;

use crate::byte_packet_buffer::BytePacketBuffer;
use crate::result_code::*;
use crate::dns_header::DnsHeader;
use crate::query_type::*;
use crate::dns_question::DnsQuestion;

use std::{net::UdpSocket, env::args};
use crate::dns_packet::DnsPacket;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;


/* == Main == */
/// Stub resolver with UDP socket that does most of the work
fn main() -> Result<()> {

    let mut qname: &str;
    let args: Vec<_> = args().collect();
    
    if args.len() > 1 {
        qname = args[1].as_str(); 
    } else {
        qname = "www.yahoo.com";
    }
    let qtype = QueryType::A;
    let qtype = QueryType::MX;

    // Using google public DNS server
    let server = ("8.8.8.8", 53);

    // Bind UDP socket to arbitrary port
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    // Build our query packet. It's important that we remember to set the
    // `recursion_desired` flag. As noted earlier, the packet id is arbitrary.
    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion::new(qname.to_string(), qtype));

    // Write packet to a buffer
    let mut req_buffer = BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    // Send it to the server using our socket:
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    // To prepare for receiving the response, we'll create a new `BytePacketBuffer`,
    // and ask the socket to write the response directly into our buffer.
    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    // As per the previous section, `DnsPacket::from_buffer()` is then used to
    // actually parse the packet after which we can print the response.

    let packet = DnsPacket::from_buffer(&mut res_buffer)?;
    println!("{:#?}", packet.header);

    println!("\nQuestions:");
    for q in packet.questions {
        println!("{:#?}", q);
    }
    println!("\nAnswers:");
    for a in packet.answers {
        println!("{:#?}", a);
    }
    println!("\nAuthorities:");
    for a in packet.authorities {
        println!("{:#?}", a);
    }
    println!("\nResources:");
    for r in packet.resources {
        println!("{:#?}", r);
    }

    Ok(())
}














