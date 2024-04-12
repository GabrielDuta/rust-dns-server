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

    let port = 2053;
    let socket = UdpSocket::bind(("0.0.0.0", port))?;
    println!("Server started ad port: {}", port);
    
    loop {
        match handle_query(&socket) {
            Ok(_) => {},
            Err(e) => eprintln!("Error: {}", e),
        }
    }
}

fn lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket> {
    // Forward requests to Google's public DNS server
    let server = ("8.8.8.8", 53);

    // Bind UDP socket to arbitrary port
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();

    // Build our query packet. It's important that we remember to set the
    // `recursion_desired` flag. The packet id is arbitrary.
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

    // `DnsPacket::from_buffer()` is then used to
    // actually parse the packet after which we can print the response.
    DnsPacket::from_buffer(&mut res_buffer)
}

/// Handle a single incoming packet
fn handle_query(socket: &UdpSocket) -> Result<()> {


    let mut req_buffer = BytePacketBuffer::new();

    // 'rcv_from()' will wait for a request and put it into the buffer
    // The function returns (data_lenght, source_address), whe are not interested
    // in the data_lenght
    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    // Parse the request
    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;
    
    // Create and initialzie response packet
    let mut response = DnsPacket::new();
    response.header.id = request.header.id;
    response.header.recursion_desired = true;
    response.header.recursion_available = true;
    response.header.response = true;

    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        if let Ok(result) = lookup(&question.name, question.qtype) {
            response.questions.push(question);
            response.header.rescode = result.header.rescode;

            for res in result.answers {
                println!("Answer: {:?}", res);
                response.answers.push(res);
            }
            for res in result.authorities {
                println!("Authorities: {:?}", res);
                response.authorities.push(res);
            }
            for res in result.resources {
                println!("Resources: {:?}", res);
                response.resources.push(res);
            }
        }
    }
    else {
        response.header.rescode = ResultCode::SERVFAIL;
    }
    
    let mut res_buffer = BytePacketBuffer::new();
    response.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}
